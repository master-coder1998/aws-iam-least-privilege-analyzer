"""
Lambda Handler — orchestrates the full IAM analysis pipeline.

Triggered by EventBridge Scheduler (daily) or manual invocation.
Designed for idempotency: re-running on the same day updates existing
findings rather than creating duplicates.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3

from src.analyzer.crawler import IAMCrawler
from src.scoring.risk_scorer import RiskScorer, Severity
from src.remediation.policy_generator import RemediationGenerator
from src.integrations.security_hub import SecurityHubIntegration

# ── Configuration from environment (set by Terraform) ──────────────
ORG_ACCOUNT_ID = os.environ["ORG_ACCOUNT_ID"]
CLOUDTRAIL_LAKE_DATA_STORE_ID = os.environ["CLOUDTRAIL_LAKE_DATA_STORE_ID"]
DYNAMODB_TABLE = os.environ["DYNAMODB_TABLE"]
S3_REMEDIATION_BUCKET = os.environ["S3_REMEDIATION_BUCKET"]
SNS_WEEKLY_DIGEST_TOPIC = os.environ.get("SNS_WEEKLY_DIGEST_TOPIC", "")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
SECURITY_ACCOUNT_ID = os.environ["SECURITY_ACCOUNT_ID"]
MIN_SEVERITY_FOR_SECHUB = os.environ.get("MIN_SEVERITY_FOR_SECHUB", "MEDIUM")
EXTERNAL_ID = os.environ.get("CROSS_ACCOUNT_EXTERNAL_ID", None)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ── AWS Clients ─────────────────────────────────────────────────────
dynamodb = boto3.resource("dynamodb", region_name=REGION)
table = dynamodb.Table(DYNAMODB_TABLE)
s3 = boto3.client("s3", region_name=REGION)


def handler(event: dict, context: Any) -> dict:
    """
    Lambda entry point.

    event schema:
    {
      "manual_trigger": bool (optional, default false),
      "accounts": "all" | ["123456789012", ...] (optional, default "all"),
      "dry_run": bool (optional, default false — dry_run skips Security Hub publish)
    }
    """
    manual = event.get("manual_trigger", False)
    account_filter = event.get("accounts", "all")
    dry_run = event.get("dry_run", False)

    logger.info(
        "IAM analyzer starting — manual=%s, accounts=%s, dry_run=%s",
        manual,
        account_filter,
        dry_run,
    )

    crawler = IAMCrawler(
        org_account_id=ORG_ACCOUNT_ID,
        cloudtrail_lake_data_store_id=CLOUDTRAIL_LAKE_DATA_STORE_ID,
        region=REGION,
        external_id=EXTERNAL_ID,
    )
    scorer = RiskScorer()
    remediator = RemediationGenerator()
    sechub = SecurityHubIntegration(region=REGION)

    min_severity = Severity[MIN_SEVERITY_FOR_SECHUB]

    run_summary = {
        "run_id": _run_id(),
        "started_at": datetime.now(tz=timezone.utc).isoformat(),
        "accounts_analyzed": 0,
        "roles_analyzed": 0,
        "critical_findings": 0,
        "high_findings": 0,
        "medium_findings": 0,
        "low_findings": 0,
        "sechub_published": 0,
        "sechub_failed": 0,
        "errors": [],
    }

    all_scores = []

    for account_id, roles in crawler.crawl_all_accounts():
        if account_filter != "all" and account_id not in account_filter:
            continue

        run_summary["accounts_analyzed"] += 1
        aa_findings = crawler.get_access_analyzer_findings(account_id)
        _aa_by_role = {f.role_arn: f for f in aa_findings}

        for role in roles:
            try:
                run_summary["roles_analyzed"] += 1

                # Build effective actions from all policy sources
                effective_actions = _extract_effective_actions(role)

                # Score
                risk = scorer.score(
                    principal_arn=role.role_arn,
                    account_id=account_id,
                    effective_actions=effective_actions,
                    trust_policy=role.assume_role_policy,
                    last_used=role.last_used,
                    tags=role.tags,
                )
                all_scores.append(risk)

                # Count by severity
                sev_key = f"{risk.severity.value.lower()}_findings"
                run_summary[sev_key] = run_summary.get(sev_key, 0) + 1

                # Generate remediation policy from CloudTrail
                usage = crawler.get_cloudtrail_usage(role.role_arn)
                remediation = remediator.generate(
                    role_arn=role.role_arn,
                    account_id=account_id,
                    usage_records=usage,
                )

                # Persist to DynamoDB and S3
                _persist_findings(role.role_arn, account_id, risk, remediation)

                logger.info(
                    "Processed %s in %s: score=%d (%s), esc_paths=%d",
                    role.role_name,
                    account_id,
                    risk.composite_score,
                    risk.severity.value,
                    len(risk.escalation_paths),
                )

            except Exception as e:
                logger.exception(
                    "Error processing role %s in %s: %s",
                    role.role_arn,
                    account_id,
                    str(e),
                )
                run_summary["errors"].append({
                    "account": account_id,
                    "role": role.role_arn,
                    "error": str(e),
                })

    # Publish to Security Hub
    if not dry_run and all_scores:
        result = sechub.publish_findings(
            risk_scores=all_scores,
            security_account_id=SECURITY_ACCOUNT_ID,
            min_severity=min_severity,
        )
        run_summary["sechub_published"] = result["imported"]
        run_summary["sechub_failed"] = result["failed"]

    run_summary["completed_at"] = datetime.now(tz=timezone.utc).isoformat()

    logger.info("Run complete: %s", json.dumps(run_summary, indent=2))

    # Store run summary
    _store_run_summary(run_summary)

    return {
        "statusCode": 200,
        "body": run_summary,
    }


def _extract_effective_actions(role) -> list[str]:
    """
    Extracts a flat list of IAM actions from all attached and inline policies.

    Note: This is a simplified extraction. Full effective permission calculation
    requires IAM Policy Simulator to correctly handle:
    - Permission boundary intersection
    - SCP filtering
    - Condition key evaluation

    For roles with CRITICAL initial scores, the integration module
    calls IAM Policy Simulator for precise effective permissions.
    """
    actions = []

    for policy in role.attached_policies:
        doc = policy.get("document", {})
        actions.extend(_extract_actions_from_document(doc))

    for policy in role.inline_policies:
        doc = policy.get("document", {})
        actions.extend(_extract_actions_from_document(doc))

    return list(set(actions))


def _extract_actions_from_document(policy_doc: dict) -> list[str]:
    actions = []
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        actions.extend(raw)
    return actions


def _persist_findings(role_arn, account_id, risk, remediation) -> None:
    """Stores findings to DynamoDB and remediation policy to S3."""
    now = datetime.now(tz=timezone.utc).isoformat()

    # DynamoDB: upsert finding with history tracking
    table.put_item(Item={
        "pk": f"ROLE#{account_id}#{role_arn}",
        "sk": f"SCORE#{now[:10]}",  # daily partition
        "role_arn": role_arn,
        "account_id": account_id,
        "composite_score": risk.composite_score,
        "severity": risk.severity.value,
        "escalation_paths": [e.path.id for e in risk.escalation_paths],
        "dimensions": {d.name: d.score for d in risk.dimensions},
        "scored_at": now,
        "ttl": int(datetime.now(tz=timezone.utc).timestamp()) + (90 * 86400),  # 90-day TTL
    })

    # S3: remediation artifact
    role_name = role_arn.split("/")[-1]
    s3_key = f"remediation/{account_id}/{role_name}/{now[:10]}.json"
    s3.put_object(
        Bucket=S3_REMEDIATION_BUCKET,
        Key=s3_key,
        Body=remediation.to_json(),
        ContentType="application/json",
        ServerSideEncryption="aws:kms",
        Metadata={
            "role-arn": role_arn,
            "account-id": account_id,
            "composite-score": str(risk.composite_score),
            "severity": risk.severity.value,
        },
    )


def _store_run_summary(summary: dict) -> None:
    """Stores run summary to DynamoDB for operational visibility."""
    try:
        table.put_item(Item={
            "pk": f"RUN#{summary['run_id']}",
            "sk": "SUMMARY",
            **{k: str(v) if isinstance(v, (int, float)) else v
               for k, v in summary.items()},
            "ttl": int(datetime.now(tz=timezone.utc).timestamp()) + (365 * 86400),
        })
    except Exception as e:
        logger.error("Failed to store run summary: %s", e)


def _run_id() -> str:
    """Deterministic daily run ID for idempotency."""
    return f"run-{datetime.now(tz=timezone.utc).strftime('%Y%m%d')}"
