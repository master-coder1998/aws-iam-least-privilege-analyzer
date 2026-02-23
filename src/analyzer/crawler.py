"""
IAM Crawler — cross-account role assumption, policy collection, and
CloudTrail Lake usage queries across all AWS Organizations accounts.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

MEMBER_ROLE_NAME = "MemberSecurityAuditRole"
CLOUDTRAIL_LOOKBACK_DAYS = 90
SESSION_NAME = "iam-analyzer-crawler"


@dataclass
class IAMRoleProfile:
    account_id: str
    role_arn: str
    role_name: str
    create_date: datetime
    last_used: datetime | None
    assume_role_policy: dict[str, Any]
    attached_policies: list[dict[str, Any]] = field(default_factory=list)
    inline_policies: list[dict[str, Any]] = field(default_factory=list)
    permission_boundaries: dict[str, Any] | None = None
    tags: dict[str, Any] = field(default_factory=dict)


@dataclass
class UsageRecord:
    event_source: str       # e.g. "s3.amazonaws.com"
    event_name: str         # e.g. "GetObject"
    resources: list[str]    # ARNs accessed
    count: int
    last_seen: datetime


@dataclass
class AccessAnalyzerFinding:
    finding_id: str
    role_arn: str
    unused_actions: list[str]
    unused_services: list[str]
    last_accessed: datetime | None
    status: str             # ACTIVE, ARCHIVED, RESOLVED


class OrgAccountIterator:
    """Yields all active account IDs in the AWS Organization."""

    def __init__(self, org_client: boto3.client) -> None:
        self._org = org_client

    def __iter__(self) -> Iterator[str]:
        paginator = self._org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for account in page["Accounts"]:
                if account["Status"] == "ACTIVE":
                    yield account["Id"]


class CrossAccountSession:
    """
    Assumes MemberSecurityAuditRole in a member account and returns
    service clients scoped to that account.

    Uses session tags to enable attribute-based access control on
    the assumed role — auditable in CloudTrail with full context.
    """

    def __init__(
        self,
        account_id: str,
        region: str = "us-east-1",
        external_id: str | None = None,
    ) -> None:
        self.account_id = account_id
        self.region = region
        self._external_id = external_id
        self._session: boto3.Session | None = None

    def __enter__(self) -> CrossAccountSession:
        sts = boto3.client("sts")
        role_arn = (
            f"arn:aws:iam::{self.account_id}:role/{MEMBER_ROLE_NAME}"
        )

        assume_kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": SESSION_NAME,
            "DurationSeconds": 3600,
            "Tags": [
                {"Key": "Analyzer", "Value": "IAMLeastPrivilege"},
                {"Key": "TriggeredBy", "Value": "SecurityAutomation"},
            ],
        }
        if self._external_id:
            assume_kwargs["ExternalId"] = self._external_id

        try:
            creds = sts.assume_role(**assume_kwargs)["Credentials"]
        except ClientError as e:
            logger.error(
                "Failed to assume role in account %s: %s",
                self.account_id,
                e.response["Error"]["Code"],
            )
            raise

        self._session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.region,
        )
        return self

    def __exit__(self, *_: object) -> None:
        self._session = None

    def client(self, service: str) -> boto3.client:
        if self._session is None:
            raise RuntimeError("CrossAccountSession not entered")
        return self._session.client(service)


class IAMCrawler:
    """
    Crawls all IAM roles across all accounts in an AWS Organization.

    Design decisions:
    - Pagination is handled explicitly; never assume a single API call
      returns complete results.
    - Effective permission calculation requests all four policy types:
      identity-based, resource-based, SCPs, and permission boundaries.
      Most tools only examine identity-based policies.
    - We request inline policies separately from managed policies because
      inline policies are frequently overlooked in manual reviews.
    """

    def __init__(
        self,
        org_account_id: str,
        cloudtrail_lake_data_store_id: str,
        region: str = "us-east-1",
        external_id: str | None = None,
    ) -> None:
        self._org_account_id = org_account_id
        self._ct_data_store_id = cloudtrail_lake_data_store_id
        self._region = region
        self._external_id = external_id
        self._org_client = boto3.client("organizations")
        self._ct_client = boto3.client("cloudtrail", region_name=region)

    def crawl_all_accounts(self) -> Iterator[tuple[str, list[IAMRoleProfile]]]:
        """
        Yields (account_id, [IAMRoleProfile, ...]) for each org account.
        Uses a generator so the caller can process accounts incrementally
        rather than loading the entire org into memory.
        """
        for account_id in OrgAccountIterator(self._org_client):
            try:
                roles = list(self._crawl_account(account_id))
                logger.info(
                    "Crawled account %s: %d roles found",
                    account_id,
                    len(roles),
                )
                yield account_id, roles
            except ClientError as e:
                logger.error(
                    "Skipping account %s — assume role failed: %s",
                    account_id,
                    e.response["Error"]["Code"],
                )
                # Don't abort the entire org crawl for one failed account.
                # The Security Hub integration will surface this as a gap finding.

    def _crawl_account(self, account_id: str) -> Iterator[IAMRoleProfile]:
        with CrossAccountSession(
            account_id, self._region, self._external_id
        ) as session:
            iam = session.client("iam")
            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page["Roles"]:
                    yield self._build_role_profile(iam, account_id, role)

    def _build_role_profile(
        self,
        iam: boto3.client,
        account_id: str,
        role_summary: dict[str, Any],
    ) -> IAMRoleProfile:
        role_name = role_summary["RoleName"]
        role_arn = role_summary["Arn"]

        # Attached managed policies
        attached = []
        paginator = iam.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_ref in page["AttachedPolicies"]:
                policy_detail = self._get_policy_document(
                    iam, policy_ref["PolicyArn"]
                )
                attached.append({
                    "arn": policy_ref["PolicyArn"],
                    "name": policy_ref["PolicyName"],
                    "document": policy_detail,
                })

        # Inline policies — these are frequently missed in manual reviews
        inline = []
        paginator = iam.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page["PolicyNames"]:
                resp = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name,
                )
                inline.append({
                    "name": policy_name,
                    "document": resp["PolicyDocument"],
                })

        # Permission boundary
        boundary = None
        if "PermissionsBoundary" in role_summary:
            boundary_arn = role_summary["PermissionsBoundary"]["PermissionsBoundaryArn"]
            boundary = {
                "arn": boundary_arn,
                "document": self._get_policy_document(iam, boundary_arn),
            }

        # Last used
        last_used = None
        role_detail = iam.get_role(RoleName=role_name)["Role"]
        if "RoleLastUsed" in role_detail and "LastUsedDate" in role_detail["RoleLastUsed"]:
            last_used = role_detail["RoleLastUsed"]["LastUsedDate"]

        # Tags
        tags = {}
        try:
            tag_resp = iam.list_role_tags(RoleName=role_name)
            tags = {t["Key"]: t["Value"] for t in tag_resp.get("Tags", [])}
        except ClientError:
            pass

        return IAMRoleProfile(
            account_id=account_id,
            role_arn=role_arn,
            role_name=role_name,
            create_date=role_summary["CreateDate"],
            last_used=last_used,
            assume_role_policy=role_summary["AssumeRolePolicyDocument"],
            attached_policies=attached,
            inline_policies=inline,
            permission_boundaries=boundary,
            tags=tags,
        )

    def _get_policy_document(self, iam: boto3.client, policy_arn: str) -> dict[str, Any]:
        """Fetches the current default version of a managed policy."""
        policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy["DefaultVersionId"],
        )
        return cast(dict[str, Any], version["PolicyVersion"]["Document"])

    def get_cloudtrail_usage(self, role_arn: str) -> list[UsageRecord]:
        """
        Queries CloudTrail Lake for actual API usage by this role
        over the lookback window.

        CloudTrail Lake is preferred over S3-based CloudTrail because:
        - SQL-queryable: can aggregate by service/action/resource efficiently
        - No need to manage Athena tables or Glue crawlers
        - Cost is per-query, not per-byte-scanned (better for targeted queries)
        - Results include requestParameters which gives us resource ARNs

        Known limitation: some older AWS services do not emit CloudTrail
        events for all API calls. Services with known gaps are flagged
        in the remediation output.
        """
        start = (
            datetime.now(tz=UTC) - timedelta(days=CLOUDTRAIL_LOOKBACK_DAYS)
        ).strftime("%Y-%m-%d %H:%M:%S")

        # CloudTrail Lake uses Athena-like SQL
        query = f"""
        SELECT
            eventSource,
            eventName,
            COALESCE(
                json_extract_scalar(requestParameters, '$.bucketName'),
                json_extract_scalar(requestParameters, '$.functionName'),
                json_extract_scalar(requestParameters, '$.roleName'),
                'unknown'
            ) AS resource,
            COUNT(*) AS call_count,
            MAX(eventTime) AS last_seen
        FROM {self._ct_data_store_id}
        WHERE
            userIdentity.arn = '{role_arn}'
            AND eventTime > '{start}'
            AND errorCode IS NULL
        GROUP BY eventSource, eventName, resource
        ORDER BY call_count DESC
        """

        try:
            resp = self._ct_client.start_query(QueryStatement=query)
            query_id = resp["QueryId"]

            # Poll for completion (CloudTrail Lake queries are async)
            result = self._wait_for_query(query_id)
            return self._parse_usage_results(result)

        except ClientError as e:
            logger.warning(
                "CloudTrail Lake query failed for %s: %s — "
                "remediation will be unavailable for this role",
                role_arn,
                e.response["Error"]["Code"],
            )
            return []

    def _wait_for_query(self, query_id: str, timeout_seconds: int = 120) -> list[dict[str, Any]]:
        """Polls CloudTrail Lake query until complete or timeout."""
        import time

        deadline = datetime.now(tz=UTC) + timedelta(seconds=timeout_seconds)

        while datetime.now(tz=UTC) < deadline:
            resp = self._ct_client.get_query_results(QueryId=query_id)
            status = resp.get("QueryStatus")

            if status == "FINISHED":
                return cast(list[dict[str, Any]], resp.get("QueryResultRows", []))
            if status in ("FAILED", "CANCELLED", "TIMED_OUT"):
                raise RuntimeError(
                    f"CloudTrail Lake query {query_id} ended with status {status}"
                )

            time.sleep(5)

        raise TimeoutError(
            f"CloudTrail Lake query {query_id} did not complete in {timeout_seconds}s"
        )

    def _parse_usage_results(self, rows: list[dict[str, Any]]) -> list[UsageRecord]:
        records = []
        for row in rows:
            columns = row.get("QueryResultColumns", [])
            values = {c["Key"]: c["Value"] for c in columns}

            service = values.get("eventSource", "").replace(".amazonaws.com", "")
            action = values.get("eventName", "")
            resource = values.get("resource", "*")

            records.append(UsageRecord(
                event_source=service,
                event_name=action,
                resources=[resource] if resource != "unknown" else [],
                count=int(values.get("call_count", 0)),
                last_seen=datetime.fromisoformat(
                    values.get("last_seen", datetime.now(tz=UTC).isoformat())
                ),
            ))

        return records

    def get_access_analyzer_findings(
        self, account_id: str
    ) -> list[AccessAnalyzerFinding]:
        """
        Pulls IAM Access Analyzer findings for unused permissions.
        Requires Access Analyzer to be enabled in each member account.
        We consume these findings rather than re-implementing unused
        permission detection — Access Analyzer owns that capability.
        """
        findings = []

        with CrossAccountSession(account_id, self._region) as session:
            aa = session.client("accessanalyzer")

            try:
                analyzers = aa.list_analyzers(type="ACCOUNT")["analyzers"]
                if not analyzers:
                    logger.warning(
                        "No Access Analyzer found in account %s. "
                        "Enable org-level delegated admin for full coverage.",
                        account_id,
                    )
                    return []

                analyzer_arn = analyzers[0]["arn"]
                paginator = aa.get_paginator("list_findings_v2")

                for page in paginator.paginate(analyzerArn=analyzer_arn):
                    for f in page["findings"]:
                        if f.get("findingType") == "UnusedIAMRole":
                            findings.append(AccessAnalyzerFinding(
                                finding_id=f["id"],
                                role_arn=f["resource"],
                                unused_actions=f.get("findingDetails", {}).get(
                                    "unusedPermissionDetails", {}
                                ).get("actions", []),
                                unused_services=f.get("findingDetails", {}).get(
                                    "unusedPermissionDetails", {}
                                ).get("services", []),
                                last_accessed=f.get("findingDetails", {}).get(
                                    "unusedPermissionDetails", {}
                                ).get("lastAccessed"),
                                status=f["status"],
                            ))

            except ClientError as e:
                logger.error(
                    "Failed to fetch Access Analyzer findings for %s: %s",
                    account_id,
                    e.response["Error"]["Code"],
                )

        return findings
