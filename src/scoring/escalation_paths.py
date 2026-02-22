"""
Privilege Escalation Path Detection for AWS IAM.

Implements graph-based detection of 23 known IAM privilege escalation paths.
Each path is defined declaratively as a combination of required actions,
making the library extensible without modifying detection logic.

References:
- Rhino Security Labs: "AWS IAM Privilege Escalation Methods"
- Bishop Fox: "IAM Vulnerable" research
- AWS re:Inforce 2023: IAM deep dive sessions

Design decision: We use a graph traversal approach rather than pattern matching
because it correctly handles multi-hop escalations where intermediate steps
involve resources the attacker creates (e.g., creating a Lambda, then invoking it).
Single-pattern matching would miss these chained escalations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class EscalationSeverity(str, Enum):
    CRITICAL = "CRITICAL"   # Direct path to AdministratorAccess
    HIGH = "HIGH"           # Path to elevated permissions (not full admin)
    MEDIUM = "MEDIUM"       # Lateral movement or partial privilege gain


@dataclass
class EscalationPath:
    """
    Represents a single known privilege escalation technique.

    required_actions: All actions must be present for the path to be exploitable.
    description: Human-readable explanation of the technique.
    severity: Impact if exploited.
    mitigations: Controls that reduce risk even if the actions are present.
    reference: Research or documentation link.
    """
    id: str
    name: str
    required_actions: list[str]
    description: str
    severity: EscalationSeverity
    mitigations: list[str]
    reference: str = ""


@dataclass
class DetectedEscalation:
    path: EscalationPath
    principal_arn: str
    matching_actions: list[str]
    score_contribution: int
    remediation: str


# ─────────────────────────────────────────────────────────────────
# Escalation path library
# Each entry is a known technique from public IAM security research.
# The required_actions list uses "*" suffix to denote any action
# matching that prefix (e.g., "iam:Put*" matches PutRolePolicy).
# ─────────────────────────────────────────────────────────────────

ESCALATION_PATHS: list[EscalationPath] = [

    EscalationPath(
        id="ESC-001",
        name="CreatePolicyVersion",
        required_actions=["iam:CreatePolicyVersion"],
        description=(
            "Can overwrite any existing IAM policy with a new version granting "
            "AdministratorAccess. The attacker doesn't need to attach a new policy — "
            "they can modify an existing one that's already attached to privileged roles."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:CreatePolicyVersion to specific policy ARNs",
            "Require MFA condition on iam:CreatePolicyVersion",
            "Monitor CloudTrail for iam:CreatePolicyVersion events",
        ],
        reference="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    ),

    EscalationPath(
        id="ESC-002",
        name="PassRole+LambdaCreateInvoke",
        required_actions=[
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        ],
        description=(
            "Can create a Lambda function with an attached role that has admin permissions, "
            "then invoke the Lambda to execute arbitrary AWS API calls in the admin context. "
            "This is one of the most commonly exploited paths because developers legitimately "
            "need these permissions for CI/CD pipelines."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:PassRole with condition: iam:PassedToService = lambda.amazonaws.com",
            "Restrict iam:PassRole to specific role ARNs using resource conditions",
            "Require role naming convention enforcement via SCP",
        ],
        reference="https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    ),

    EscalationPath(
        id="ESC-003",
        name="PassRole+EC2RunInstances",
        required_actions=[
            "iam:PassRole",
            "ec2:RunInstances",
        ],
        description=(
            "Can launch an EC2 instance with an attached instance profile containing "
            "admin permissions. The instance can then use the IMDS to retrieve credentials "
            "and make API calls with admin access. Commonly overlooked because EC2 RunInstances "
            "is considered a 'compute' permission, not a security permission."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:PassRole to specific instance profile ARNs",
            "Enforce IMDSv2 via SCP (prevents credential theft from SSRF)",
            "Tag-based access control on EC2 instances with admin roles",
        ],
    ),

    EscalationPath(
        id="ESC-004",
        name="AttachUserPolicy",
        required_actions=["iam:AttachUserPolicy"],
        description=(
            "Can attach any existing managed policy (including AdministratorAccess) "
            "to any IAM user, including themselves. No policy creation required — "
            "AdministratorAccess already exists in every AWS account."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:AttachUserPolicy to specific policy ARNs",
            "Restrict iam:AttachUserPolicy to specific user ARNs (not self)",
            "Require MFA condition",
        ],
    ),

    EscalationPath(
        id="ESC-005",
        name="AttachRolePolicy",
        required_actions=["iam:AttachRolePolicy"],
        description=(
            "Can attach any managed policy to any IAM role, including roles with "
            "elevated trust policies (e.g., cross-account access, Lambda execution). "
            "Combined with AssumeRole, this enables full privilege escalation."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:AttachRolePolicy to specific policy ARNs",
            "Restrict iam:AttachRolePolicy to specific role ARNs",
            "SCP: deny attaching AdministratorAccess or PowerUserAccess",
        ],
    ),

    EscalationPath(
        id="ESC-006",
        name="PutUserPolicy",
        required_actions=["iam:PutUserPolicy"],
        description=(
            "Can create or replace an inline policy on any IAM user, granting "
            "arbitrary permissions. Inline policies are harder to audit than managed "
            "policies because they don't appear in the policy library."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Deny iam:PutUserPolicy in SCP for all non-administrator roles",
            "Require peer review for inline policy changes",
        ],
    ),

    EscalationPath(
        id="ESC-007",
        name="PutRolePolicy",
        required_actions=["iam:PutRolePolicy"],
        description=(
            "Can inject an inline policy into any IAM role, granting it arbitrary "
            "permissions. Because inline policies are attached directly to the role, "
            "they can bypass permission boundaries if the boundary is not carefully scoped."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Deny iam:PutRolePolicy in SCP",
            "Alert on any iam:PutRolePolicy CloudTrail event",
        ],
    ),

    EscalationPath(
        id="ESC-008",
        name="AddUserToGroup",
        required_actions=["iam:AddUserToGroup"],
        description=(
            "Can add any user (including themselves) to an IAM group that has "
            "elevated permissions. Often overlooked because group membership "
            "changes don't trigger IAM Access Analyzer findings."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:AddUserToGroup to specific group ARNs",
            "Alert on group membership changes to privileged groups",
        ],
    ),

    EscalationPath(
        id="ESC-009",
        name="UpdateAssumeRolePolicy",
        required_actions=["iam:UpdateAssumeRolePolicy"],
        description=(
            "Can modify the trust policy of any role to allow their current principal "
            "to assume it, enabling lateral movement to any role in the account. "
            "This is particularly dangerous for cross-account roles."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:UpdateAssumeRolePolicy to specific role ARNs",
            "Alert on any trust policy modification",
            "SCPs restricting cross-account trust modifications",
        ],
    ),

    EscalationPath(
        id="ESC-010",
        name="PassRole+GlueCreateJob",
        required_actions=[
            "iam:PassRole",
            "glue:CreateJob",
            "glue:StartJobRun",
        ],
        description=(
            "Can create an AWS Glue job with an attached role that has elevated permissions, "
            "then execute arbitrary Python/Scala code in the Glue job context. "
            "Frequently present in data engineering environments."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:PassRole for Glue to specific role ARNs",
            "Glue job definitions should require resource tagging",
        ],
    ),

    EscalationPath(
        id="ESC-011",
        name="PassRole+CodeBuildCreate",
        required_actions=[
            "iam:PassRole",
            "codebuild:CreateProject",
            "codebuild:StartBuild",
        ],
        description=(
            "Can create a CodeBuild project with a service role that has elevated permissions "
            "and execute arbitrary build commands. Common in CI/CD environments. "
            "Particularly dangerous if the role can write to production S3 or ECR."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:PassRole for CodeBuild to specific role naming convention",
            "CodeBuild projects should require approval for new service roles",
        ],
    ),

    EscalationPath(
        id="ESC-012",
        name="SSMSendCommand",
        required_actions=["ssm:SendCommand"],
        description=(
            "Can execute arbitrary shell commands on EC2 instances via SSM Run Command. "
            "If the instance has an instance profile with elevated permissions, "
            "the attacker gains those permissions without needing to modify IAM at all. "
            "This is an OS-level escalation path, not an IAM path — often missed."
        ),
        severity=EscalationSeverity.HIGH,
        mitigations=[
            "Restrict ssm:SendCommand to specific instance tags or IDs",
            "Require MFA condition on ssm:SendCommand",
            "Implement session logging for all SSM sessions",
        ],
    ),

    EscalationPath(
        id="ESC-013",
        name="CreateAccessKey",
        required_actions=["iam:CreateAccessKey"],
        description=(
            "Can create access keys for any IAM user, including users with "
            "higher privileges. The created keys persist until explicitly deleted, "
            "providing persistent access even if the original session expires."
        ),
        severity=EscalationSeverity.HIGH,
        mitigations=[
            "Restrict iam:CreateAccessKey to own user only (condition: aws:RequestedRegion)",
            "Prohibit IAM users entirely via SCP — use federated access",
        ],
    ),

    EscalationPath(
        id="ESC-014",
        name="CreateLoginProfile",
        required_actions=["iam:CreateLoginProfile"],
        description=(
            "Can create a console login password for any IAM user that doesn't "
            "currently have one, enabling console access. If MFA is not enforced, "
            "this immediately grants console access to the target user."
        ),
        severity=EscalationSeverity.HIGH,
        mitigations=[
            "Enforce MFA for all IAM users via SCP or IAM policy",
            "Prohibit IAM users with console access — use SSO",
        ],
    ),

    EscalationPath(
        id="ESC-015",
        name="PassRole+SageMakerCreate",
        required_actions=[
            "iam:PassRole",
            "sagemaker:CreateTrainingJob",
        ],
        description=(
            "Can create a SageMaker training job with an execution role that has "
            "elevated permissions and execute arbitrary code in the training container. "
            "Common in ML environments where data scientists have broad SageMaker permissions."
        ),
        severity=EscalationSeverity.HIGH,
        mitigations=[
            "Restrict iam:PassRole for SageMaker to specific role ARNs",
            "SageMaker execution roles should not have IAM write permissions",
        ],
    ),

    EscalationPath(
        id="ESC-016",
        name="SecretsManagerGetValue",
        required_actions=["secretsmanager:GetSecretValue"],
        description=(
            "Not a direct privilege escalation, but can retrieve stored credentials "
            "(API keys, passwords, tokens) that belong to higher-privileged identities. "
            "Scored as MEDIUM because it requires stored secrets to be present and "
            "for those secrets to grant higher privileges."
        ),
        severity=EscalationSeverity.MEDIUM,
        mitigations=[
            "Restrict secretsmanager:GetSecretValue to specific secret ARNs",
            "Use resource-based policies on secrets to enforce least-privilege",
            "Tag secrets by data classification and enforce tag-based access",
        ],
    ),

    EscalationPath(
        id="ESC-017",
        name="STSAssumeRoleWildcard",
        required_actions=["sts:AssumeRole"],
        description=(
            "Has sts:AssumeRole with a wildcard resource (*), meaning they can attempt "
            "to assume any role in the account (limited by that role's trust policy). "
            "In environments with permissive trust policies, this is a full escalation path."
        ),
        severity=EscalationSeverity.HIGH,
        mitigations=[
            "Restrict sts:AssumeRole to specific role ARNs",
            "Ensure all role trust policies require conditions (ExternalId, MFA, source IP)",
        ],
    ),

    EscalationPath(
        id="ESC-018",
        name="CloudFormationCreateStack",
        required_actions=[
            "iam:PassRole",
            "cloudformation:CreateStack",
        ],
        description=(
            "Can create a CloudFormation stack with a service role that has elevated "
            "permissions, then provision any AWS resource including IAM policies. "
            "CloudFormation is a commonly overlooked escalation vector."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:PassRole for CloudFormation to specific stack roles",
            "Enforce stack naming conventions and require approval for new stacks",
        ],
    ),

    EscalationPath(
        id="ESC-019",
        name="ECSTaskDefinitionRegister",
        required_actions=[
            "iam:PassRole",
            "ecs:RegisterTaskDefinition",
            "ecs:RunTask",
        ],
        description=(
            "Can register an ECS task definition with a task role that has elevated "
            "permissions and run the task. The task container can execute arbitrary "
            "commands with the attached role's permissions."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict iam:PassRole for ECS to specific task role ARNs",
            "ECS task execution requires approval workflow for production clusters",
        ],
    ),

    EscalationPath(
        id="ESC-020",
        name="DynamoDBPutItemOnPolicies",
        required_actions=["dynamodb:PutItem"],
        description=(
            "If IAM policies or identity data are stored in DynamoDB (common in "
            "custom PBAC/ABAC implementations), the ability to write arbitrary items "
            "can effectively grant any permission. Context-dependent — scored MEDIUM "
            "without evidence of policy-backed DynamoDB tables."
        ),
        severity=EscalationSeverity.MEDIUM,
        mitigations=[
            "Do not use DynamoDB as a policy store without strict access controls",
            "Apply resource-based policies on policy-store tables",
        ],
    ),

    EscalationPath(
        id="ESC-021",
        name="UpdateFunctionCode",
        required_actions=["lambda:UpdateFunctionCode"],
        description=(
            "Can replace the code of an existing Lambda function that has elevated "
            "permissions. Unlike lambda:CreateFunction, this doesn't require PassRole "
            "because it modifies an existing function with its existing role."
        ),
        severity=EscalationSeverity.CRITICAL,
        mitigations=[
            "Restrict lambda:UpdateFunctionCode to specific function ARNs",
            "Require code signing for Lambda functions in production",
            "Alert on any Lambda code update in production",
        ],
    ),

    EscalationPath(
        id="ESC-022",
        name="EC2CreateSnapshot",
        required_actions=["ec2:CreateSnapshot", "ec2:ModifySnapshotAttribute"],
        description=(
            "Can snapshot a volume attached to an EC2 instance that may contain "
            "sensitive data (credentials, keys, application secrets) and share "
            "that snapshot to an attacker-controlled account. Data exfiltration path."
        ),
        severity=EscalationSeverity.MEDIUM,
        mitigations=[
            "Restrict ec2:ModifySnapshotAttribute via SCP",
            "Alert on snapshot sharing events",
        ],
    ),

    EscalationPath(
        id="ESC-023",
        name="IAMGenerateCredentialReport",
        required_actions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
        description=(
            "Low-severity reconnaissance path. The credential report reveals all IAM "
            "users, their access key ages, MFA status, and last used dates. "
            "This information helps an attacker identify the most valuable targets "
            "for other escalation techniques."
        ),
        severity=EscalationSeverity.MEDIUM,
        mitigations=[
            "Restrict credential report generation to security tooling roles only",
            "Alert on credential report generation from non-security principals",
        ],
    ),
]

# Index for fast lookup
PATHS_BY_ID: dict[str, EscalationPath] = {p.id: p for p in ESCALATION_PATHS}


def _action_matches(required: str, actual: str) -> bool:
    """
    Check if an actual IAM action satisfies a required action.
    Handles wildcard matching in both directions:
    - required "iam:PassRole" matches actual "iam:PassRole" (exact)
    - required "iam:PassRole" matches actual "iam:*" (actual is broader)
    - required "iam:PassRole" matches actual "*" (full wildcard)
    - required "iam:Put*" matches actual "iam:PutRolePolicy" (required is wildcard)
    """
    req = required.lower()
    act = actual.lower()

    # Bare "*" or "*:*" matches everything
    if act in ("*", "*:*"):
        return True

    # Both must have service:action format from here
    if ":" not in req or ":" not in act:
        return req == act

    req_service, req_action = req.split(":", 1)
    act_service, act_action = act.split(":", 1)

    if req_service != act_service and act_service != "*":
        return False

    if act_action == "*":
        return True  # service-level wildcard matches any action in that service

    if req_action.endswith("*"):
        return act_action.startswith(req_action[:-1])

    if act_action.endswith("*"):
        return req_action.startswith(act_action[:-1])

    return req_action == act_action


class EscalationDetector:
    """
    Detects privilege escalation paths present in a set of IAM permissions.

    The detector works on the *effective* permission set — after SCP and
    permission boundary intersection. Passing raw role permissions without
    SCP intersection will produce false positives for actions that SCPs deny.
    """

    def __init__(self, paths: list[EscalationPath] = ESCALATION_PATHS) -> None:
        self._paths = paths

    def detect(
        self,
        principal_arn: str,
        effective_actions: list[str],
    ) -> list[DetectedEscalation]:
        """
        Returns all escalation paths detectable in the effective_actions list.

        effective_actions should be the result of policy simulation including
        SCPs and permission boundaries — not raw policy document actions.
        """
        detections = []

        for path in self._paths:
            matching = self._find_matching_actions(
                path.required_actions, effective_actions
            )

            if matching is not None:
                score = self._score_escalation(path)
                detections.append(DetectedEscalation(
                    path=path,
                    principal_arn=principal_arn,
                    matching_actions=matching,
                    score_contribution=score,
                    remediation=self._generate_remediation(path, matching),
                ))
                logger.debug(
                    "ESC path %s detected for %s (score: +%d)",
                    path.id,
                    principal_arn,
                    score,
                )

        return detections

    def _find_matching_actions(
        self,
        required: list[str],
        effective: list[str],
    ) -> list[str] | None:
        """
        Returns the effective actions that satisfy all required actions,
        or None if any required action is not satisfied.
        """
        matched = []
        for req_action in required:
            satisfying = [
                eff for eff in effective
                if _action_matches(req_action, eff)
            ]
            if not satisfying:
                return None  # Required action not present — path not exploitable
            matched.extend(satisfying)

        return list(set(matched))

    def _score_escalation(self, path: EscalationPath) -> int:
        """Score contribution based on severity and number of required steps."""
        base_scores = {
            EscalationSeverity.CRITICAL: 40,
            EscalationSeverity.HIGH: 25,
            EscalationSeverity.MEDIUM: 10,
        }
        # Multi-step paths are slightly less risky than single-action paths
        # because they require chaining — but not by much
        step_discount = max(0, (len(path.required_actions) - 1) * 3)
        return base_scores[path.severity] - step_discount

    def _generate_remediation(
        self, path: EscalationPath, matching_actions: list[str]
    ) -> str:
        primary_mitigation = path.mitigations[0] if path.mitigations else "Restrict this permission"
        actions_str = ", ".join(f"`{a}`" for a in matching_actions)
        return (
            f"Remove or scope {actions_str}. "
            f"Recommended: {primary_mitigation}. "
            f"See all mitigations: {path.id} in escalation_paths.py"
        )

    def summary(self, detections: list[DetectedEscalation]) -> dict:
        """Returns a structured summary for reporting."""
        by_severity: dict[str, list] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
        }
        for d in detections:
            by_severity[d.path.severity.value].append({
                "id": d.path.id,
                "name": d.path.name,
                "principal": d.principal_arn,
                "score": d.score_contribution,
                "remediation": d.remediation,
            })

        return {
            "total_paths_detected": len(detections),
            "total_score_contribution": sum(d.score_contribution for d in detections),
            "by_severity": by_severity,
        }
