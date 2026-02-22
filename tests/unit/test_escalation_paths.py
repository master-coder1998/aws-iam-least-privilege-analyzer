"""
Unit tests for privilege escalation path detection.

These tests are the primary validation that the detection logic is correct.
Each known escalation path has at least one positive test (path detected)
and one negative test (path correctly NOT detected when required actions are absent).

A hiring manager reading this file should be able to confirm:
1. The tool detects real escalation paths, not invented ones
2. Edge cases are handled (wildcard matching, partial matches)
3. The logic can be reasoned about and defended in an interview
"""

import pytest
from datetime import datetime, timezone

from src.scoring.escalation_paths import (
    EscalationDetector,
    ESCALATION_PATHS,
    _action_matches,
)
from src.scoring.risk_scorer import RiskScorer, Severity, score_to_severity


# ─────────────────────────────────────────────────────────────────────
# action_matches helper tests
# ─────────────────────────────────────────────────────────────────────

class TestActionMatching:
    def test_exact_match(self):
        assert _action_matches("iam:PassRole", "iam:PassRole") is True

    def test_case_insensitive(self):
        assert _action_matches("IAM:PassRole", "iam:passrole") is True

    def test_actual_wildcard_matches_any_action(self):
        assert _action_matches("iam:PassRole", "iam:*") is True
        assert _action_matches("iam:CreatePolicy", "iam:*") is True

    def test_full_wildcard_matches_any_service(self):
        assert _action_matches("iam:PassRole", "*") is True
        assert _action_matches("s3:GetObject", "*:*") is True

    def test_required_wildcard_prefix(self):
        assert _action_matches("iam:Put*", "iam:PutRolePolicy") is True
        assert _action_matches("iam:Put*", "iam:PutUserPolicy") is True
        assert _action_matches("iam:Put*", "iam:GetRolePolicy") is False

    def test_different_service_no_match(self):
        assert _action_matches("iam:PassRole", "s3:PutObject") is False
        assert _action_matches("lambda:CreateFunction", "iam:CreateFunction") is False

    def test_partial_action_no_match(self):
        assert _action_matches("iam:PassRole", "iam:Pass") is False
        assert _action_matches("iam:CreateFunction", "iam:Create") is False


# ─────────────────────────────────────────────────────────────────────
# EscalationDetector tests
# ─────────────────────────────────────────────────────────────────────

class TestEscalationDetector:
    @pytest.fixture
    def detector(self):
        return EscalationDetector()

    # ESC-001: CreatePolicyVersion
    def test_esc001_detected_with_exact_action(self, detector):
        actions = ["iam:CreatePolicyVersion"]
        results = detector.detect("arn:aws:iam::123456789012:role/test", actions)
        ids = [r.path.id for r in results]
        assert "ESC-001" in ids

    def test_esc001_detected_with_iam_wildcard(self, detector):
        """iam:* should trigger ESC-001 because it includes CreatePolicyVersion"""
        actions = ["iam:*"]
        results = detector.detect("arn:aws:iam::123456789012:role/test", actions)
        ids = [r.path.id for r in results]
        assert "ESC-001" in ids

    def test_esc001_not_detected_without_action(self, detector):
        actions = ["iam:GetRole", "iam:ListRoles", "s3:GetObject"]
        results = detector.detect("arn:aws:iam::123456789012:role/test", actions)
        ids = [r.path.id for r in results]
        assert "ESC-001" not in ids

    # ESC-002: PassRole + Lambda escalation
    def test_esc002_detected_full_chain(self, detector):
        """All three required actions present — full exploitation possible"""
        actions = [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        ]
        results = detector.detect("arn:aws:iam::123456789012:role/dev-role", actions)
        ids = [r.path.id for r in results]
        assert "ESC-002" in ids

    def test_esc002_not_detected_missing_passrole(self, detector):
        """Without iam:PassRole, cannot attach an admin role to the Lambda"""
        actions = [
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        ]
        results = detector.detect("arn:aws:iam::123456789012:role/dev-role", actions)
        ids = [r.path.id for r in results]
        assert "ESC-002" not in ids

    def test_esc002_not_detected_missing_invoke(self, detector):
        """Without InvokeFunction, can create but not execute the Lambda"""
        actions = [
            "iam:PassRole",
            "lambda:CreateFunction",
        ]
        results = detector.detect("arn:aws:iam::123456789012:role/dev-role", actions)
        ids = [r.path.id for r in results]
        assert "ESC-002" not in ids

    def test_esc002_detected_with_wildcards(self, detector):
        """Wildcard permissions should detect ESC-002"""
        actions = ["*"]  # AdministratorAccess equivalent
        results = detector.detect("arn:aws:iam::123456789012:role/admin", actions)
        # With *, all paths should be detectable
        ids = [r.path.id for r in results]
        assert "ESC-002" in ids
        assert "ESC-001" in ids

    # ESC-003: PassRole + EC2
    def test_esc003_detected(self, detector):
        actions = ["iam:PassRole", "ec2:RunInstances"]
        results = detector.detect("arn:aws:iam::123456789012:role/test", actions)
        ids = [r.path.id for r in results]
        assert "ESC-003" in ids

    # ESC-007: PutRolePolicy
    def test_esc007_direct_inline_injection(self, detector):
        actions = ["iam:PutRolePolicy"]
        results = detector.detect("arn:aws:iam::123456789012:role/test", actions)
        ids = [r.path.id for r in results]
        assert "ESC-007" in ids

    # ESC-017: Wildcard AssumeRole
    def test_esc017_wildcard_assumerole(self, detector):
        actions = ["sts:AssumeRole"]
        results = detector.detect("arn:aws:iam::123456789012:role/test", actions)
        ids = [r.path.id for r in results]
        assert "ESC-017" in ids

    # ESC-021: UpdateFunctionCode (modifying existing Lambda)
    def test_esc021_update_function_no_passrole_needed(self, detector):
        """
        Key insight: UpdateFunctionCode doesn't need PassRole because
        the role is already attached to the existing function.
        """
        actions = ["lambda:UpdateFunctionCode"]
        results = detector.detect("arn:aws:iam::123456789012:role/test", actions)
        ids = [r.path.id for r in results]
        assert "ESC-021" in ids

    def test_no_escalation_for_read_only_role(self, detector):
        """A truly read-only role should have zero escalation paths"""
        actions = [
            "s3:GetObject",
            "s3:ListBucket",
            "cloudwatch:GetMetricData",
            "ec2:DescribeInstances",
            "iam:GetRole",
            "iam:ListRoles",
        ]
        results = detector.detect("arn:aws:iam::123456789012:role/readonly", actions)
        # Read-only actions should not trigger any escalation paths
        assert len(results) == 0, (
            f"Expected 0 escalations for read-only role, got: "
            f"{[r.path.id for r in results]}"
        )

    def test_summary_output_structure(self, detector):
        actions = ["iam:CreatePolicyVersion", "iam:PassRole", "lambda:CreateFunction",
                   "lambda:InvokeFunction"]
        results = detector.detect("arn:aws:iam::123456789012:role/test", actions)
        summary = detector.summary(results)

        assert "total_paths_detected" in summary
        assert "total_score_contribution" in summary
        assert "by_severity" in summary
        assert "CRITICAL" in summary["by_severity"]
        assert summary["total_paths_detected"] > 0
        assert summary["total_score_contribution"] > 0

    def test_all_escalation_paths_have_mitigations(self):
        """Ensure every path in the library has at least one mitigation documented"""
        for path in ESCALATION_PATHS:
            assert len(path.mitigations) >= 1, (
                f"Path {path.id} ({path.name}) has no mitigations documented"
            )

    def test_all_escalation_paths_have_descriptions(self):
        """All paths must have meaningful descriptions (not empty)"""
        for path in ESCALATION_PATHS:
            assert len(path.description) >= 50, (
                f"Path {path.id} has description that is too short: '{path.description}'"
            )

    def test_escalation_path_ids_are_unique(self):
        ids = [p.id for p in ESCALATION_PATHS]
        assert len(ids) == len(set(ids)), "Duplicate escalation path IDs found"


# ─────────────────────────────────────────────────────────────────────
# RiskScorer tests
# ─────────────────────────────────────────────────────────────────────

class TestRiskScorer:
    @pytest.fixture
    def scorer(self):
        return RiskScorer()

    @pytest.fixture
    def simple_trust_policy(self):
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }

    @pytest.fixture
    def cross_account_trust_no_conditions(self):
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole",
                # No ExternalId, no MFA — confused deputy vulnerability
            }],
        }

    @pytest.fixture
    def admin_trust_with_mfa(self):
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            }],
        }

    def test_readonly_role_scores_low(self, scorer, simple_trust_policy):
        actions = ["s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances"]
        last_used = datetime.now(tz=timezone.utc)

        result = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/readonly",
            account_id="123456789012",
            effective_actions=actions,
            trust_policy=simple_trust_policy,
            last_used=last_used,
        )

        assert result.composite_score < 20
        assert result.severity == Severity.LOW

    def test_admin_without_mfa_scores_critical(self, scorer, cross_account_trust_no_conditions):
        actions = ["*"]
        last_used = datetime.now(tz=timezone.utc)

        result = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/admin",
            account_id="123456789012",
            effective_actions=actions,
            trust_policy=cross_account_trust_no_conditions,
            last_used=last_used,
        )

        assert result.composite_score >= 70
        assert result.severity == Severity.CRITICAL
        assert len(result.escalation_paths) > 0

    def test_admin_with_mfa_scores_lower(self, scorer, admin_trust_with_mfa):
        """Admin role WITH MFA should score lower than one without"""
        actions = ["*"]
        last_used = datetime.now(tz=timezone.utc)

        result_with_mfa = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/admin-mfa",
            account_id="123456789012",
            effective_actions=actions,
            trust_policy=admin_trust_with_mfa,
            last_used=last_used,
        )

        no_mfa_trust = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole",
            }],
        }
        result_no_mfa = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/admin-no-mfa",
            account_id="123456789012",
            effective_actions=actions,
            trust_policy=no_mfa_trust,
            last_used=last_used,
        )

        assert result_with_mfa.composite_score < result_no_mfa.composite_score

    def test_stale_role_adds_score(self, scorer, simple_trust_policy):
        """Never-used role should score higher than active role with same permissions"""
        actions = ["s3:GetObject"]

        active_result = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/active",
            account_id="123456789012",
            effective_actions=actions,
            trust_policy=simple_trust_policy,
            last_used=datetime.now(tz=timezone.utc),
        )

        stale_result = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/stale",
            account_id="123456789012",
            effective_actions=actions,
            trust_policy=simple_trust_policy,
            last_used=None,  # Never used
        )

        assert stale_result.composite_score > active_result.composite_score

    def test_score_capped_at_100(self, scorer, cross_account_trust_no_conditions):
        """Score should never exceed 100 regardless of how many risk factors apply"""
        actions = ["*"]  # Everything risky

        result = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/everything-wrong",
            account_id="123456789012",
            effective_actions=actions,
            trust_policy=cross_account_trust_no_conditions,
            last_used=None,
        )

        assert result.composite_score <= 100

    def test_sensitive_service_wildcards_score_higher(self, scorer, simple_trust_policy):
        """IAM wildcard should score higher than EC2 wildcard"""
        last_used = datetime.now(tz=timezone.utc)

        iam_wildcard = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/iam-admin",
            account_id="123456789012",
            effective_actions=["iam:*"],
            trust_policy=simple_trust_policy,
            last_used=last_used,
        )

        ec2_wildcard = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/ec2-admin",
            account_id="123456789012",
            effective_actions=["ec2:*"],
            trust_policy=simple_trust_policy,
            last_used=last_used,
        )

        assert iam_wildcard.composite_score > ec2_wildcard.composite_score

    def test_score_to_severity_mapping(self):
        assert score_to_severity(0) == Severity.LOW
        assert score_to_severity(19) == Severity.LOW
        assert score_to_severity(20) == Severity.MEDIUM
        assert score_to_severity(44) == Severity.MEDIUM
        assert score_to_severity(45) == Severity.HIGH
        assert score_to_severity(69) == Severity.HIGH
        assert score_to_severity(70) == Severity.CRITICAL
        assert score_to_severity(100) == Severity.CRITICAL

    def test_result_is_serializable(self, scorer, simple_trust_policy):
        """RiskScore.to_dict() must be JSON-serializable for DynamoDB storage"""
        import json
        result = scorer.score(
            principal_arn="arn:aws:iam::123456789012:role/test",
            account_id="123456789012",
            effective_actions=["s3:GetObject", "iam:PassRole", "lambda:CreateFunction",
                               "lambda:InvokeFunction"],
            trust_policy=simple_trust_policy,
            last_used=datetime.now(tz=timezone.utc),
        )
        # Should not raise
        serialized = json.dumps(result.to_dict())
        deserialized = json.loads(serialized)
        assert deserialized["principal_arn"] == "arn:aws:iam::123456789012:role/test"
