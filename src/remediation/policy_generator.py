"""
Remediation Generator — produces least-privilege IAM policy from
actual CloudTrail usage data.

Critical design constraint: The generated policy is a STARTING POINT
for human review, not a push-button replacement. This is documented
in every output artifact and the README. Automated policy replacement
without review is out of scope and would be irresponsible.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..analyzer.crawler import UsageRecord

logger = logging.getLogger(__name__)

# Services with known CloudTrail coverage gaps — remediation will flag these
CLOUDTRAIL_COVERAGE_GAPS: dict[str, str] = {
    "s3": "S3 data events require explicit CloudTrail data event configuration. "
           "Object-level operations (GetObject, PutObject) may not be logged without it.",
    "iot": "AWS IoT has partial CloudTrail coverage for data plane operations.",
    "kinesis": "Kinesis data stream PutRecord/GetRecords are not logged to CloudTrail.",
    "sqs": "SQS SendMessage/ReceiveMessage are not logged to CloudTrail by default.",
    "sns": "SNS Publish is not logged to CloudTrail.",
    "codecommit": "CodeCommit git operations (push, pull) are not CloudTrail events.",
}

# ARN patterns for resource minimization
ARN_PATTERN = re.compile(
    r"arn:aws:(?P<service>[^:]+):(?P<region>[^:]*):(?P<account>[^:]*):(?P<resource>.+)"
)


@dataclass
class PolicyStatement:
    effect: str
    actions: list[str]
    resources: list[str]
    conditions: dict = field(default_factory=dict)
    comment: str = ""  # Stored as Sid for traceability

    def to_dict(self) -> dict:
        stmt: dict[str, Any] = {
            "Effect": self.effect,
            "Action": sorted(self.actions),
            "Resource": self.resources if len(self.resources) > 1 else self.resources[0],
        }
        if self.conditions:
            stmt["Condition"] = self.conditions
        if self.comment:
            # Sid must match pattern [A-Za-z0-9]+
            sid = re.sub(r"[^A-Za-z0-9]", "", self.comment)[:64]
            if sid:
                stmt["Sid"] = sid
        return stmt


@dataclass
class RemediationPolicy:
    role_arn: str
    account_id: str
    lookback_days: int
    generated_at: datetime
    policy_document: dict
    coverage_warnings: list[str]
    usage_summary: dict
    caveats: list[str]

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "metadata": {
                "role_arn": self.role_arn,
                "generated_at": self.generated_at.isoformat(),
                "lookback_days": self.lookback_days,
                "WARNING": (
                    "This policy was generated from CloudTrail usage data and is a "
                    "STARTING POINT for human review. Do not apply without review. "
                    "See caveats field for known gaps."
                ),
                "caveats": self.caveats,
                "coverage_warnings": self.coverage_warnings,
                "usage_summary": self.usage_summary,
            },
            "recommended_policy": self.policy_document,
        }, indent=indent)


class RemediationGenerator:
    """
    Generates a least-privilege IAM policy recommendation from
    CloudTrail usage records.

    The generation process:
    1. Group usage records by service
    2. Check for CloudTrail coverage gaps per service
    3. Minimize resource ARNs (specific > prefix > wildcard)
    4. Group actions by resource scope to avoid redundant statements
    5. Generate policy with metadata and caveats
    """

    def generate(
        self,
        role_arn: str,
        account_id: str,
        usage_records: list[UsageRecord],
        lookback_days: int = 90,
    ) -> RemediationPolicy:
        """
        Produces a RemediationPolicy from actual usage records.

        Returns a policy with no statements if no usage records are found —
        this indicates either a stale role or CloudTrail coverage gaps.
        """
        if not usage_records:
            return self._empty_policy(role_arn, account_id, lookback_days)

        # Detect coverage gaps
        used_services = {
            r.event_source.replace(".amazonaws.com", "")
            for r in usage_records
        }
        coverage_warnings = [
            CLOUDTRAIL_COVERAGE_GAPS[svc]
            for svc in used_services
            if svc in CLOUDTRAIL_COVERAGE_GAPS
        ]

        # Group by (service, action) → list of resources
        usage_map: dict[tuple[str, str], list[str]] = {}
        for record in usage_records:
            service = record.event_source.replace(".amazonaws.com", "")
            key = (service, record.event_name)
            usage_map.setdefault(key, []).extend(record.resources)

        # Build policy statements grouped by service
        statements = self._build_statements(usage_map, account_id)

        # Usage summary for metadata
        usage_summary = {
            "total_api_calls_analyzed": sum(r.count for r in usage_records),
            "unique_actions": len(usage_map),
            "services_used": sorted(used_services),
            "date_range": f"last {lookback_days} days",
        }

        caveats = self._generate_caveats(used_services, lookback_days)

        policy_document = {
            "Version": "2012-10-17",
            "Statement": [s.to_dict() for s in statements],
        }

        return RemediationPolicy(
            role_arn=role_arn,
            account_id=account_id,
            lookback_days=lookback_days,
            generated_at=datetime.now(tz=timezone.utc),
            policy_document=policy_document,
            coverage_warnings=coverage_warnings,
            usage_summary=usage_summary,
            caveats=caveats,
        )

    def _build_statements(
        self,
        usage_map: dict[tuple[str, str], list[str]],
        account_id: str,
    ) -> list[PolicyStatement]:
        """
        Groups (service, action) pairs into policy statements.

        Strategy:
        - Actions against specific, identifiable resources → scoped statement
        - Actions against wildcard/unknown resources → service-level statement
          with a comment noting the limitation
        """
        # Group by minimized resource set
        resource_to_actions: dict[str, list[str]] = {}

        for (service, action), resources in usage_map.items():
            iam_action = f"{service}:{action}"
            minimized = self._minimize_resources(resources, account_id)
            resource_key = "|".join(sorted(minimized))
            resource_to_actions.setdefault(resource_key, []).append(iam_action)

        statements = []
        for resource_key, actions in resource_to_actions.items():
            resources = resource_key.split("|")
            comment = (
                "LeastPrivilegeFromCloudTrail"
                if resources != ["*"]
                else "UnknownResourcesRequireReview"
            )
            statements.append(PolicyStatement(
                effect="Allow",
                actions=sorted(set(actions)),
                resources=resources,
                comment=comment,
            ))

        return statements

    def _minimize_resources(
        self, resources: list[str], account_id: str
    ) -> list[str]:
        """
        Minimizes a list of resource ARNs to the most specific ARN
        pattern that covers all observed access.

        Priority: specific ARN > prefix ARN > service wildcard > full wildcard

        This is the most nuanced part of policy generation. We err on
        the side of being slightly broader than strictly necessary to
        avoid breaking applications due to missing permissions.
        """
        if not resources or all(not r for r in resources):
            return ["*"]  # Unknown resources — cannot scope

        # Filter out empty/null values
        clean = [r for r in resources if r and r != "unknown"]
        if not clean:
            return ["*"]

        # If only one unique resource, return it directly
        unique = list(set(clean))
        if len(unique) == 1:
            return unique

        # Try to find common ARN prefix
        prefixes = self._find_common_arn_prefixes(unique, account_id)
        if prefixes:
            return prefixes

        # Fall back to listing all resources (up to a reasonable limit)
        if len(unique) <= 10:
            return sorted(unique)

        # Too many unique resources — use service-level wildcard with comment
        sample = sorted(unique)[:3]
        logger.warning(
            "Could not minimize %d resources — using wildcard. "
            "Sample: %s",
            len(unique),
            sample,
        )
        return ["*"]

    def _find_common_arn_prefixes(
        self, arns: list[str], account_id: str
    ) -> list[str] | None:
        """
        Finds the minimal set of ARN prefixes that covers all provided ARNs.

        Example:
          Input:  arn:aws:s3:::my-bucket/folder1/file1.txt
                  arn:aws:s3:::my-bucket/folder1/file2.txt
                  arn:aws:s3:::my-bucket/folder2/file1.txt
          Output: arn:aws:s3:::my-bucket/*
        """
        parsed = []
        for arn in arns:
            match = ARN_PATTERN.match(arn)
            if match:
                parsed.append(match.groupdict())

        if not parsed:
            return None

        # Group by service
        by_service: dict[str, list[dict]] = {}
        for p in parsed:
            by_service.setdefault(p["service"], []).append(p)

        prefixes = []
        for service, parts in by_service.items():
            resources = [p["resource"] for p in parts]
            region = parts[0]["region"] or "*"
            account = parts[0]["account"] or account_id

            # Find longest common prefix of resources
            if len(resources) == 1:
                prefixes.append(
                    f"arn:aws:{service}:{region}:{account}:{resources[0]}"
                )
            else:
                common = self._longest_common_prefix(resources)
                if common:
                    prefixes.append(
                        f"arn:aws:{service}:{region}:{account}:{common}*"
                    )
                else:
                    prefixes.append(
                        f"arn:aws:{service}:{region}:{account}:*"
                    )

        return prefixes if prefixes else None

    def _longest_common_prefix(self, strings: list[str]) -> str:
        if not strings:
            return ""
        prefix = strings[0]
        for s in strings[1:]:
            while not s.startswith(prefix):
                prefix = prefix[:-1]
                if not prefix:
                    return ""
        return prefix

    def _generate_caveats(
        self, used_services: set[str], lookback_days: int
    ) -> list[str]:
        caveats = [
            f"This policy covers API calls observed in the last {lookback_days} days only. "
            f"Infrequent operations (quarterly jobs, annual audits, disaster recovery) "
            f"may not appear and could be absent from this policy.",
            "Resource ARNs are minimized but may not be perfectly scoped. "
            "Review all wildcard (*) resource entries carefully.",
            "Emergency break-glass scenarios typically require broader permissions "
            "than day-to-day usage. Ensure break-glass procedures are documented "
            "separately from this policy.",
            "This policy does not include deny statements. Consider adding explicit "
            "denies for high-risk actions that should never be used.",
        ]

        gap_services = used_services.intersection(CLOUDTRAIL_COVERAGE_GAPS.keys())
        if gap_services:
            caveats.append(
                f"Services with CloudTrail coverage gaps detected: "
                f"{', '.join(gap_services)}. "
                f"These services may have uncaptured API calls not reflected in this policy."
            )

        return caveats

    def _empty_policy(
        self, role_arn: str, account_id: str, lookback_days: int
    ) -> RemediationPolicy:
        return RemediationPolicy(
            role_arn=role_arn,
            account_id=account_id,
            lookback_days=lookback_days,
            generated_at=datetime.now(tz=timezone.utc),
            policy_document={"Version": "2012-10-17", "Statement": []},
            coverage_warnings=["No CloudTrail usage found. Role may be stale or "
                               "CloudTrail may not cover its API calls."],
            usage_summary={"total_api_calls_analyzed": 0},
            caveats=[
                "No usage detected. If this role has active workloads, check whether "
                "CloudTrail is enabled and whether data events are configured.",
                "An empty policy effectively denies all actions — do not apply "
                "without investigating why no usage was detected.",
            ],
        )
