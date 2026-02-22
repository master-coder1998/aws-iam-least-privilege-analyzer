################################################################################
# Member Account Security Audit Role
#
# Deployed to ALL member accounts via AWS CloudFormation StackSets.
# This role allows the analyzer (in the security tooling account) to
# read IAM data and Access Analyzer findings for analysis.
#
# Principle applied: ReadOnlyAccess + specific security service reads.
# No write permissions are granted in member accounts.
################################################################################

resource "aws_iam_role" "member_security_audit" {
  name        = "MemberSecurityAuditRole"
  description = "Allows IAM Analyzer in security account to read IAM and Access Analyzer data"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSecurityAccountAssumption"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.security_account_id}:role/iam-analyzer-lambda-execution"
        }
        Action = "sts:AssumeRole"
        Condition = {
          # ExternalId prevents confused deputy attacks from other roles
          # in the security account accidentally assuming this role
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
          # Require session tags to be set (enforces auditable context)
          StringEquals = {
            "aws:RequestedRegion" = var.analyzer_region
          }
        }
      }
    ]
  })

  max_session_duration = 3600 # 1 hour max — sufficient for a full account crawl

  tags = {
    Purpose       = "SecurityAudit"
    ManagedBy     = "StackSets"
    AllowedCaller = "IAMLeastPrivilegeAnalyzer"
  }
}

resource "aws_iam_role_policy" "member_security_audit" {
  name = "iam-analyzer-read-permissions"
  role = aws_iam_role.member_security_audit.id

  # Scoped to exactly what the analyzer needs — no more.
  # ReadOnlyAccess managed policy is intentionally NOT used because it's
  # too broad (includes data plane reads we don't need).
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMReadForAnalysis"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListRoles",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListRoleTags",
          "iam:ListPolicies",
          "iam:ListPolicyVersions",
          "iam:GetAccountAuthorizationDetails",
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
        ]
        Resource = "*"
      },
      {
        Sid    = "AccessAnalyzerRead"
        Effect = "Allow"
        Action = [
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ListFindings",
          "access-analyzer:ListFindingsV2",
          "access-analyzer:GetFinding",
          "access-analyzer:GetFindingV2",
        ]
        Resource = "*"
      },
      {
        Sid    = "OrganizationsSCPRead"
        Effect = "Allow"
        Action = [
          "organizations:DescribeAccount",
          "organizations:ListPoliciesForTarget",
          "organizations:DescribePolicy",
        ]
        Resource = "*"
      }
    ]
  })
}

variable "security_account_id" {
  description = "Account ID of the security tooling account running the analyzer"
  type        = string
}

variable "external_id" {
  description = "ExternalId condition value for the trust policy (prevents confused deputy)"
  type        = string
  sensitive   = true
}

variable "analyzer_region" {
  description = "Region where the analyzer Lambda runs"
  type        = string
  default     = "us-east-1"
}
