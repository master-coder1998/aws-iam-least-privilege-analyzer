"""
Security Hub Integration — publishes IAM risk findings as custom
Security Hub findings using the AWS Security Finding Format (ASFF).

Design decision: We use Security Hub rather than a custom notification
system because Security Hub:
- Integrates with existing SOC workflows and ticketing
- Provides deduplication (same finding ID = update, not new finding)
- Supports suppression rules for known-acceptable risks
- Enables cross-account finding aggregation via Organizations integration
- Allows correlation with other security findings (GuardDuty, Inspector)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from ..scoring.risk_scorer import RiskScore, Severity

logger = logging.getLogger(__name__)

# Custom product ARN format for Security Hub custom integrations
PRODUCT_ARN_TEMPLATE = "arn:aws:securityhub:{region}:{account}:product/{account}/default"

# Security Hub batch limit
SH_BATCH_SIZE = 100

# Severity label mapping
SEVERITY_MAP = {
    Severity.CRITICAL: {"Label": "CRITICAL", "Normalized": 90},
    Severity.HIGH:     {"Label": "HIGH",     "Normalized": 70},
    Severity.MEDIUM:   {"Label": "MEDIUM",   "Normalized": 40},
    Severity.LOW:      {"Label": "LOW",      "Normalized": 20},
    Severity.INFORMATIONAL: {"Label": "INFORMATIONAL", "Normalized": 0},
}


class SecurityHubIntegration:
    """
    Publishes IAM risk findings to AWS Security Hub using ASFF.

    Finding deduplication strategy:
    - Finding ID is deterministic: hash(account_id + role_arn + finding_type)
    - Re-running the analyzer updates existing findings rather than creating duplicates
    - Resolved findings (score dropped below threshold) are updated to RESOLVED status
    """

    def __init__(
        self,
        region: str = "us-east-1",
        generator_id: str = "iam-least-privilege-analyzer",
    ) -> None:
        self._sh = boto3.client("securityhub", region_name=region)
        self._region = region
        self._generator_id = generator_id

    def publish_findings(
        self,
        risk_scores: list[RiskScore],
        security_account_id: str,
        min_severity: Severity = Severity.MEDIUM,
    ) -> dict[str, int]:
        """
        Publishes a batch of RiskScore objects to Security Hub.
        Filters out findings below min_severity threshold.
        Returns counts of imported/failed findings.
        """
        publishable = [
            rs for rs in risk_scores
            if self._severity_ordinal(rs.severity) >= self._severity_ordinal(min_severity)
        ]

        if not publishable:
            logger.info("No findings above %s threshold to publish", min_severity.value)
            return {"imported": 0, "failed": 0}

        asff_findings = [
            self._to_asff(rs, security_account_id)
            for rs in publishable
        ]

        return self._batch_import(asff_findings)

    def resolve_findings(
        self,
        role_arns: list[str],
        account_id: str,
        resolution_reason: str = "Remediated",
    ) -> None:
        """
        Marks previously-published findings as RESOLVED.
        Called when a role's risk score drops below the publishing threshold,
        indicating the issue has been remediated.
        """
        finding_ids = [
            self._finding_id(account_id, arn)
            for arn in role_arns
        ]
        product_arn = PRODUCT_ARN_TEMPLATE.format(
            region=self._region,
            account=account_id,
        )

        try:
            self._sh.batch_update_findings(
                FindingIdentifiers=[
                    {"Id": fid, "ProductArn": product_arn}
                    for fid in finding_ids
                ],
                Workflow={"Status": "RESOLVED"},
                Note={
                    "Text": resolution_reason,
                    "UpdatedBy": self._generator_id,
                },
            )
            logger.info("Resolved %d Security Hub findings", len(finding_ids))
        except ClientError as e:
            logger.error("Failed to resolve findings: %s", e)

    def _to_asff(self, risk_score: RiskScore, account_id: str) -> dict[str, Any]:
        """
        Converts a RiskScore to AWS Security Finding Format (ASFF).

        ASFF is the standard schema for all Security Hub findings.
        Using the correct schema ensures compatibility with Security Hub
        automation rules, suppression, and third-party integrations.
        """
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # Collect top findings across all dimensions
        all_findings = []
        for dim in risk_score.dimensions:
            all_findings.extend(dim.findings)

        # Truncate description to Security Hub's 1024-char limit
        description = self._build_description(risk_score, all_findings)

        # Build escalation path details for the finding
        remediation_text = self._build_remediation_text(risk_score)

        return {
            "SchemaVersion": "2018-10-08",
            "Id": self._finding_id(risk_score.account_id, risk_score.principal_arn),
            "ProductArn": PRODUCT_ARN_TEMPLATE.format(
                region=self._region,
                account=account_id,
            ),
            "GeneratorId": self._generator_id,
            "AwsAccountId": risk_score.account_id,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices/IAM"
            ],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": SEVERITY_MAP[risk_score.severity],
            "Title": (
                f"IAM Role Over-Privileged: {risk_score.principal_arn.split('/')[-1]} "
                f"[Score: {risk_score.composite_score}/100]"
            ),
            "Description": description,
            "Remediation": {
                "Recommendation": {
                    "Text": remediation_text,
                    "Url": (
                        "https://github.com/master-coder1998/aws-iam-least-privilege-analyzer"
                        "/blob/main/runbooks/remediation-guide.md"
                    ),
                }
            },
            "Resources": [
                {
                    "Type": "AwsIamRole",
                    "Id": risk_score.principal_arn,
                    "Region": self._region,
                    "Details": {
                        "AwsIamRole": {
                            "RoleId": risk_score.principal_arn,
                        }
                    },
                }
            ],
            "Compliance": {
                "Status": "FAILED" if risk_score.composite_score >= 20 else "PASSED",
                "RelatedRequirements": self._get_related_requirements(risk_score),
            },
            "FindingProviderFields": {
                "Severity": SEVERITY_MAP[risk_score.severity],
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices/IAM"
                ],
            },
            "UserDefinedFields": {
                "CompositeScore": str(risk_score.composite_score),
                "EscalationPathsDetected": str(len(risk_score.escalation_paths)),
                "EscalationPathIds": ",".join(
                    e.path.id for e in risk_score.escalation_paths
                ),
                "ScoreBreakdown": ",".join(
                    f"{d.name}:{d.score}" for d in risk_score.dimensions
                ),
            },
        }

    def _build_description(
        self, risk_score: RiskScore, all_findings: list[str]
    ) -> str:
        esc_summary = ""
        if risk_score.escalation_paths:
            top_esc = risk_score.escalation_paths[0]
            esc_summary = (
                f" [{len(risk_score.escalation_paths)} privilege escalation "
                f"path(s) detected — highest: {top_esc.path.id} {top_esc.path.name}]"
            )

        top_findings = all_findings[:3]
        finding_text = " | ".join(top_findings) if top_findings else "See full report."

        full = (
            f"IAM role has risk score {risk_score.composite_score}/100 "
            f"({risk_score.severity.value}).{esc_summary} "
            f"Top findings: {finding_text}"
        )
        # Security Hub description limit: 1024 chars
        return full[:1020] + "..." if len(full) > 1024 else full

    def _build_remediation_text(self, risk_score: RiskScore) -> str:
        steps = []

        if risk_score.escalation_paths:
            paths = ", ".join(e.path.id for e in risk_score.escalation_paths[:3])
            steps.append(f"1. Address escalation paths: {paths}")

        stale_dim = next(
            (d for d in risk_score.dimensions if d.name == "staleness" and d.score > 0),
            None,
        )
        if stale_dim:
            steps.append("2. Review whether role is still needed — consider deletion")

        steps.append(
            "3. Review auto-generated least-privilege policy in S3 remediation artifacts"
        )

        return " | ".join(steps) if steps else "Review IAM permissions and apply least-privilege policy."

    def _get_related_requirements(self, risk_score: RiskScore) -> list[str]:
        """Maps findings to compliance framework controls."""
        requirements = [
            "CIS AWS Foundations Benchmark v1.4.0/1.16",  # Ensure IAM policies are attached only to groups or roles
        ]
        if any(d.name == "admin_without_mfa" and d.score > 0 for d in risk_score.dimensions):
            requirements.extend([
                "CIS AWS Foundations Benchmark v1.4.0/1.10",  # Ensure MFA is enabled
                "SOC2/CC6.1",  # Logical and physical access controls
                "ISO 27001:2013/A.9.4.2",  # Secure log-on procedures
            ])
        if risk_score.escalation_paths:
            requirements.extend([
                "SOC2/CC6.3",  # Role-based access control
                "PCI DSS v3.2.1/7.1",  # Limit access to system components
            ])
        return requirements

    def _finding_id(self, account_id: str, role_arn: str) -> str:
        """
        Deterministic finding ID ensures re-runs update rather than
        duplicate existing findings in Security Hub.
        """
        import hashlib
        key = f"{account_id}:{role_arn}:iam-risk"
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    def _severity_ordinal(self, severity: Severity) -> int:
        order = {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order.get(severity, 0)

    def _batch_import(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        """Imports findings in batches of 100 (Security Hub API limit)."""
        total_imported = 0
        total_failed = 0

        for i in range(0, len(findings), SH_BATCH_SIZE):
            batch = findings[i: i + SH_BATCH_SIZE]
            try:
                resp = self._sh.batch_import_findings(Findings=batch)
                total_imported += resp.get("SuccessCount", 0)
                failed = resp.get("FailedCount", 0)
                total_failed += failed

                if failed:
                    for failure in resp.get("FailedFindings", []):
                        logger.error(
                            "Failed to import finding %s: %s — %s",
                            failure.get("Id"),
                            failure.get("ErrorCode"),
                            failure.get("ErrorMessage"),
                        )
            except ClientError as e:
                logger.error("Batch import failed: %s", e)
                total_failed += len(batch)

        logger.info(
            "Security Hub import complete: %d imported, %d failed",
            total_imported,
            total_failed,
        )
        return {"imported": total_imported, "failed": total_failed}
