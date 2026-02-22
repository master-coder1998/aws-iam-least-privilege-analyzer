"""
Risk Scoring Engine — composite IAM risk score across six dimensions.

Design decision: Additive scoring (sum of all factors, capped at 100)
rather than maximum-single-factor. A role with five medium risks is
more concerning than a role with one high risk, because it represents
a broader attack surface. See ADR-003 in README.md.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from .escalation_paths import DetectedEscalation, EscalationDetector

logger = logging.getLogger(__name__)

STALE_ROLE_DAYS = 90
MAX_SCORE = 100


class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # score >= 70
    HIGH = "HIGH"           # score 45–69
    MEDIUM = "MEDIUM"       # score 20–44
    LOW = "LOW"             # score < 20
    INFORMATIONAL = "INFORMATIONAL"  # special cases (e.g., service roles)


def score_to_severity(score: int) -> Severity:
    if score >= 70:
        return Severity.CRITICAL
    elif score >= 45:
        return Severity.HIGH
    elif score >= 20:
        return Severity.MEDIUM
    else:
        return Severity.LOW


@dataclass
class ScoreDimension:
    name: str
    score: int
    max_score: int
    details: str
    findings: list[str] = field(default_factory=list)


@dataclass
class RiskScore:
    principal_arn: str
    account_id: str
    composite_score: int
    severity: Severity
    dimensions: list[ScoreDimension]
    escalation_paths: list[DetectedEscalation]
    scored_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def to_dict(self) -> dict:
        return {
            "principal_arn": self.principal_arn,
            "account_id": self.account_id,
            "composite_score": self.composite_score,
            "severity": self.severity.value,
            "dimensions": [
                {
                    "name": d.name,
                    "score": d.score,
                    "max_score": d.max_score,
                    "details": d.details,
                    "findings": d.findings,
                }
                for d in self.dimensions
            ],
            "escalation_paths_detected": len(self.escalation_paths),
            "escalation_path_ids": [e.path.id for e in self.escalation_paths],
            "scored_at": self.scored_at.isoformat(),
        }


class RiskScorer:
    """
    Computes a composite risk score (0–100) for an IAM role across six dimensions:

    1. Wildcard Actions (0–30 pts)
       Detects service-level (*) and action-level wildcards.
       Weighted higher for sensitive services (IAM, STS, Organizations).

    2. Wildcard Resources (0–20 pts)
       Wildcard resources compound the risk of wildcard actions.
       Scoped wildcards (e.g., arn:aws:s3:::my-bucket/*) are penalized less.

    3. Privilege Escalation Paths (0–40 pts)
       Graph-based detection of 23 known escalation techniques.
       Single highest-severity path dominates this dimension.

    4. Cross-Account Trust Issues (0–30 pts)
       Overly permissive trust policies, missing ExternalId conditions,
       wildcard principal in trust policy.

    5. Admin Role Without MFA (0–25 pts)
       Admin-equivalent permissions without MFA condition key.

    6. Staleness (0–15 pts)
       Role unused for 90+ days represents unnecessary attack surface.
    """

    # Services where wildcard permissions are significantly higher risk
    SENSITIVE_SERVICES = frozenset({
        "iam", "sts", "organizations", "sso", "kms",
        "secretsmanager", "ssm", "cloudtrail", "config",
        "guardduty", "securityhub",
    })

    def __init__(self) -> None:
        self._escalation_detector = EscalationDetector()

    def score(
        self,
        principal_arn: str,
        account_id: str,
        effective_actions: list[str],
        trust_policy: dict,
        last_used: datetime | None,
        tags: dict[str, str] | None = None,
    ) -> RiskScore:
        """
        Computes the composite risk score for a single IAM principal.

        effective_actions: result of effective permission calculation
            (identity policy ∩ permission boundary, filtered by SCPs)
        trust_policy: the role's AssumeRolePolicyDocument
        last_used: datetime of last role usage (None = never used)
        tags: role tags — used to detect data classification context
        """
        tags = tags or {}
        dimensions = []

        # Dimension 1: Wildcard actions
        wildcard_dim = self._score_wildcard_actions(effective_actions)
        dimensions.append(wildcard_dim)

        # Dimension 2: Wildcard resources
        resource_dim = self._score_wildcard_resources(effective_actions)
        dimensions.append(resource_dim)

        # Dimension 3: Privilege escalation paths
        escalations = self._escalation_detector.detect(principal_arn, effective_actions)
        esc_dim = self._score_escalation_paths(escalations)
        dimensions.append(esc_dim)

        # Dimension 4: Cross-account trust
        trust_dim = self._score_trust_policy(trust_policy)
        dimensions.append(trust_dim)

        # Dimension 5: Admin without MFA
        admin_dim = self._score_admin_without_mfa(effective_actions, trust_policy)
        dimensions.append(admin_dim)

        # Dimension 6: Staleness
        stale_dim = self._score_staleness(last_used)
        dimensions.append(stale_dim)

        raw_score = sum(d.score for d in dimensions)
        composite = min(raw_score, MAX_SCORE)
        severity = score_to_severity(composite)

        logger.info(
            "Scored %s: %d (%s) — ESC paths: %d",
            principal_arn,
            composite,
            severity.value,
            len(escalations),
        )

        return RiskScore(
            principal_arn=principal_arn,
            account_id=account_id,
            composite_score=composite,
            severity=severity,
            dimensions=dimensions,
            escalation_paths=escalations,
        )

    def _score_wildcard_actions(self, actions: list[str]) -> ScoreDimension:
        findings = []
        score = 0

        full_wildcards = [a for a in actions if a == "*" or a == "*:*"]
        service_wildcards = [a for a in actions if a.endswith(":*") and a != "*:*"]
        sensitive_wildcards = [
            a for a in service_wildcards
            if a.split(":")[0] in self.SENSITIVE_SERVICES
        ]

        if full_wildcards:
            score += 30
            findings.append(
                f"Full wildcard action (*) grants all AWS permissions. "
                f"This is equivalent to AdministratorAccess."
            )

        elif sensitive_wildcards:
            score += min(25, len(sensitive_wildcards) * 8)
            findings.append(
                f"Wildcard actions on sensitive services: "
                f"{', '.join(sensitive_wildcards[:5])}. "
                f"These services can be used for escalation or data exfiltration."
            )

        elif service_wildcards:
            score += min(15, len(service_wildcards) * 4)
            findings.append(
                f"{len(service_wildcards)} service-level wildcards detected: "
                f"{', '.join(service_wildcards[:5])}{'...' if len(service_wildcards) > 5 else ''}. "
                f"Each wildcard includes future API actions in that service."
            )

        return ScoreDimension(
            name="wildcard_actions",
            score=score,
            max_score=30,
            details=f"{len(full_wildcards)} full wildcards, "
                    f"{len(sensitive_wildcards)} sensitive service wildcards, "
                    f"{len(service_wildcards)} total service wildcards",
            findings=findings,
        )

    def _score_wildcard_resources(self, actions: list[str]) -> ScoreDimension:
        """
        Analyzes resource scoping in the context of action permissions.
        Note: this requires the full policy document for accurate analysis.
        Here we approximate based on action patterns.

        For full accuracy, callers should pass policy statements directly.
        This is a known limitation documented in README.
        """
        findings = []
        score = 0

        # Detect common action+resource combinations that indicate wildcard resources
        broad_s3 = any(a.startswith("s3:") and "*" not in a for a in actions)
        broad_iam = any(a.startswith("iam:") for a in actions)
        broad_ec2 = any(a.startswith("ec2:") for a in actions)

        if broad_iam:
            score += 15
            findings.append(
                "IAM actions detected. Without resource scoping, these apply to all "
                "principals and policies in the account."
            )
        if broad_s3:
            score += 8
            findings.append(
                "S3 actions detected. Review whether resource ARNs are scoped to "
                "specific buckets and prefixes."
            )
        if broad_ec2:
            score += 5
            findings.append(
                "EC2 actions detected. Consider scoping to specific instance tags "
                "using tag-based conditions."
            )

        return ScoreDimension(
            name="wildcard_resources",
            score=score,
            max_score=20,
            details="Resource scoping analysis (partial — see full policy for accuracy)",
            findings=findings,
        )

    def _score_escalation_paths(
        self, escalations: list[DetectedEscalation]
    ) -> ScoreDimension:
        findings = []
        score = 0

        if escalations:
            # Take the sum of all escalation scores (they're already calibrated)
            # Cap at 40 for this dimension
            score = min(40, sum(e.score_contribution for e in escalations))
            for esc in sorted(
                escalations, key=lambda e: e.score_contribution, reverse=True
            )[:3]:
                findings.append(
                    f"[{esc.path.id}] {esc.path.name} ({esc.path.severity.value}): "
                    f"{esc.path.description[:120]}..."
                )

        return ScoreDimension(
            name="privilege_escalation_paths",
            score=score,
            max_score=40,
            details=f"{len(escalations)} escalation paths detected",
            findings=findings,
        )

    def _score_trust_policy(self, trust_policy: dict) -> ScoreDimension:
        findings = []
        score = 0

        statements = trust_policy.get("Statement", [])
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal", {})
            conditions = stmt.get("Condition", {})

            # Wildcard principal — anyone can assume this role
            if principal == "*" or principal == {"AWS": "*"}:
                score += 30
                findings.append(
                    "CRITICAL: Wildcard principal (*) in trust policy. "
                    "Any AWS account or principal can attempt to assume this role. "
                    "This is almost always a misconfiguration."
                )
                continue

            # Cross-account trust without ExternalId condition
            aws_principals = principal if isinstance(principal, list) else \
                             principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            cross_account_principals = [
                p for p in aws_principals
                if isinstance(p, str) and "arn:aws:iam::" in p
            ]

            if cross_account_principals:
                has_external_id = "StringEquals" in conditions and any(
                    "sts:ExternalId" in k
                    for k in conditions.get("StringEquals", {})
                )
                has_mfa = "Bool" in conditions and "aws:MultiFactorAuthPresent" in \
                          conditions.get("Bool", {})
                has_source_account = "StringEquals" in conditions and any(
                    "aws:SourceAccount" in k
                    for k in conditions.get("StringEquals", {})
                )

                if not any([has_external_id, has_mfa, has_source_account]):
                    score += 15
                    findings.append(
                        f"Cross-account trust without ExternalId, MFA, or source account "
                        f"condition. Principals: {', '.join(cross_account_principals[:3])}. "
                        f"This is vulnerable to confused deputy attacks."
                    )

            # Overly broad service principal
            service_principals = principal.get("Service", [])
            if isinstance(service_principals, str):
                service_principals = [service_principals]
            risky_services = [
                s for s in service_principals
                if s in ("ec2.amazonaws.com", "lambda.amazonaws.com")
                   and not conditions
            ]
            if risky_services:
                score += 5
                findings.append(
                    f"Service principal trust without conditions: {', '.join(risky_services)}. "
                    f"Consider adding aws:SourceAccount or aws:SourceArn conditions."
                )

        return ScoreDimension(
            name="cross_account_trust",
            score=min(score, 30),
            max_score=30,
            details=f"{len(statements)} trust policy statements analyzed",
            findings=findings,
        )

    def _score_admin_without_mfa(
        self, effective_actions: list[str], trust_policy: dict
    ) -> ScoreDimension:
        findings = []
        score = 0

        # Determine if this role has admin-equivalent permissions
        is_admin = (
            "*" in effective_actions
            or "*:*" in effective_actions
            or "iam:*" in effective_actions
        )

        if is_admin:
            # Check if trust policy requires MFA
            mfa_required = self._trust_requires_mfa(trust_policy)
            if not mfa_required:
                score = 25
                findings.append(
                    "Role has admin-equivalent permissions but trust policy does not "
                    "require aws:MultiFactorAuthPresent: true. Human-assumable admin "
                    "roles must require MFA."
                )
            else:
                findings.append(
                    "Admin role correctly requires MFA condition in trust policy."
                )

        return ScoreDimension(
            name="admin_without_mfa",
            score=score,
            max_score=25,
            details="Admin permission check with MFA enforcement validation",
            findings=findings,
        )

    def _trust_requires_mfa(self, trust_policy: dict) -> bool:
        for stmt in trust_policy.get("Statement", []):
            conditions = stmt.get("Condition", {})
            bool_conditions = conditions.get("Bool", {})
            if bool_conditions.get("aws:MultiFactorAuthPresent") == "true":
                return True
        return False

    def _score_staleness(self, last_used: datetime | None) -> ScoreDimension:
        findings = []
        score = 0

        now = datetime.now(tz=timezone.utc)

        if last_used is None:
            score = 15
            findings.append(
                "Role has never been used. Never-used roles represent pure attack "
                "surface with no business value. Recommend deletion or scheduled expiry."
            )
        else:
            # Normalize timezone if needed
            if last_used.tzinfo is None:
                last_used = last_used.replace(tzinfo=timezone.utc)

            days_since = (now - last_used).days

            if days_since >= 180:
                score = 15
                findings.append(
                    f"Role last used {days_since} days ago (>{STALE_ROLE_DAYS} day threshold). "
                    f"Highly likely to be abandoned. Recommend review and deletion."
                )
            elif days_since >= STALE_ROLE_DAYS:
                score = 10
                findings.append(
                    f"Role last used {days_since} days ago. "
                    f"Exceeds {STALE_ROLE_DAYS}-day staleness threshold."
                )
            elif days_since >= 30:
                score = 3
                findings.append(
                    f"Role last used {days_since} days ago. Monitor for further inactivity."
                )

        return ScoreDimension(
            name="staleness",
            score=score,
            max_score=15,
            details=f"Last used: {last_used.isoformat() if last_used else 'never'}",
            findings=findings,
        )
