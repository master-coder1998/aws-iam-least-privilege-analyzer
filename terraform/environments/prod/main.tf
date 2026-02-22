################################################################################
# IAM Least Privilege Analyzer — Terraform Infrastructure
# Deployed in the Security Tooling account
################################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  backend "s3" {
    # Populated via -backend-config in CI/CD — no hardcoded values
    # bucket = "your-terraform-state-bucket"
    # key    = "iam-analyzer/terraform.tfstate"
    # region = "us-east-1"
    # encrypt        = true
    # dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "IAMLeastPrivilegeAnalyzer"
      ManagedBy   = "Terraform"
      SecurityTool = "true"
      Owner       = "SecurityTeam"
    }
  }
}

################################################################################
# Data sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Lambda — IAM Analyzer
################################################################################

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../src"
  output_path = "${path.module}/dist/iam_analyzer.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc", "**/test_*"]
}

resource "aws_lambda_function" "iam_analyzer" {
  function_name = "iam-analyzer-crawler"
  description   = "Analyzes IAM roles across AWS Organizations for least-privilege compliance"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  handler          = "lambda_handler.handler"
  runtime          = "python3.12"
  timeout          = 900  # 15 minutes — org-wide crawl can take time
  memory_size      = 1024

  role = aws_iam_role.lambda_execution.arn

  environment {
    variables = {
      ORG_ACCOUNT_ID                 = var.org_account_id
      CLOUDTRAIL_LAKE_DATA_STORE_ID  = var.cloudtrail_lake_data_store_id
      DYNAMODB_TABLE                 = aws_dynamodb_table.findings.name
      S3_REMEDIATION_BUCKET          = aws_s3_bucket.remediation.bucket
      SNS_WEEKLY_DIGEST_TOPIC        = aws_sns_topic.weekly_digest.arn
      SECURITY_ACCOUNT_ID            = data.aws_caller_identity.current.account_id
      MIN_SEVERITY_FOR_SECHUB        = var.min_severity_for_sechub
      AWS_DEFAULT_REGION             = var.aws_region
      CROSS_ACCOUNT_EXTERNAL_ID      = var.cross_account_external_id
    }
  }

  # Dead letter queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tracing_config {
    mode = "Active"  # X-Ray tracing for performance visibility
  }

  reserved_concurrent_executions = 1  # Prevent parallel runs from duplicate findings

  depends_on = [aws_cloudwatch_log_group.lambda_logs]

  lifecycle {
    ignore_changes = [filename]  # Managed by CI/CD deployment
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/iam-analyzer-crawler"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.analyzer.arn
}

################################################################################
# EventBridge Scheduler — daily trigger
################################################################################

resource "aws_scheduler_schedule" "daily_analysis" {
  name        = "iam-analyzer-daily"
  description = "Triggers IAM least privilege analysis daily at 02:00 UTC"

  schedule_expression = "cron(0 2 * * ? *)"  # 02:00 UTC daily

  flexible_time_window {
    mode                      = "FLEXIBLE"
    maximum_window_in_minutes = 30  # Allow 30-min window to avoid thundering herd
  }

  target {
    arn      = aws_lambda_function.iam_analyzer.arn
    role_arn = aws_iam_role.scheduler.arn

    input = jsonencode({
      manual_trigger = false
      accounts       = "all"
      dry_run        = false
    })

    retry_policy {
      maximum_attempts        = 2
      maximum_event_age_in_seconds = 3600
    }
  }
}

resource "aws_lambda_permission" "allow_scheduler" {
  statement_id  = "AllowEventBridgeScheduler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_analyzer.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.daily_analysis.arn
}

################################################################################
# DynamoDB — findings store
################################################################################

resource "aws_dynamodb_table" "findings" {
  name         = "iam-analyzer-findings"
  billing_mode = "PAY_PER_REQUEST"  # On-demand — usage is bursty (daily run)
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "account_id"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  # GSI for querying by account_id + severity (Security team dashboard)
  global_secondary_index {
    name            = "account-severity-index"
    hash_key        = "account_id"
    range_key       = "severity"
    projection_type = "ALL"
  }

  # TTL — 90 days per-finding history retention
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Point-in-time recovery — protect audit history
  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.analyzer.arn
  }

  tags = {
    DataClassification = "Internal"
    Purpose            = "SecurityFindings"
  }
}

################################################################################
# S3 — remediation artifacts
################################################################################

resource "aws_s3_bucket" "remediation" {
  bucket = "${var.remediation_bucket_prefix}-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
}

resource "aws_s3_bucket_versioning" "remediation" {
  bucket = aws_s3_bucket.remediation.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "remediation" {
  bucket = aws_s3_bucket.remediation.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.analyzer.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true  # Reduces KMS API calls and costs
  }
}

resource "aws_s3_bucket_public_access_block" "remediation" {
  bucket                  = aws_s3_bucket.remediation.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "remediation" {
  bucket = aws_s3_bucket.remediation.id

  rule {
    id     = "expire-old-remediations"
    status = "Enabled"

    expiration {
      days = 365  # Keep 1 year of remediation history
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Block any cross-account or public access to remediation artifacts
resource "aws_s3_bucket_policy" "remediation" {
  bucket = aws_s3_bucket.remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.remediation.arn,
          "${aws_s3_bucket.remediation.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid    = "DenyExternalAccess"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.remediation.arn,
          "${aws_s3_bucket.remediation.arn}/*",
        ]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = var.org_id
          }
        }
      }
    ]
  })
}

################################################################################
# KMS — encryption key for all analyzer resources
################################################################################

resource "aws_kms_key" "analyzer" {
  description             = "IAM Analyzer — encrypts findings, remediation artifacts, and logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = data.aws_iam_policy_document.kms_key_policy.json
}

resource "aws_kms_alias" "analyzer" {
  name          = "alias/iam-analyzer"
  target_key_id = aws_kms_key.analyzer.key_id
}

data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid     = "EnableRootAccount"
    effect  = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowLambdaEncryption"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda_execution.arn]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

################################################################################
# SNS — weekly digest
################################################################################

resource "aws_sns_topic" "weekly_digest" {
  name              = "iam-analyzer-weekly-digest"
  kms_master_key_id = aws_kms_key.analyzer.arn
}

resource "aws_sns_topic_subscription" "security_team_email" {
  topic_arn = aws_sns_topic.weekly_digest.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

################################################################################
# SQS — Lambda dead letter queue
################################################################################

resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "iam-analyzer-dlq"
  message_retention_seconds = 1209600  # 14 days
  kms_master_key_id         = aws_kms_key.analyzer.arn
}

################################################################################
# IAM — Lambda execution role (least privilege)
################################################################################

resource "aws_iam_role" "lambda_execution" {
  name = "iam-analyzer-lambda-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_execution" {
  name   = "iam-analyzer-lambda-permissions"
  role   = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AssumeOrgMemberRoles"
        Effect = "Allow"
        Action = "sts:AssumeRole"
        # Scoped to the specific role name pattern — not wildcard
        Resource = "arn:aws:iam::*:role/MemberSecurityAuditRole"
        Condition = {
          StringEquals = { "sts:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid    = "ListOrgAccounts"
        Effect = "Allow"
        Action = [
          "organizations:ListAccounts",
          "organizations:DescribeOrganization",
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBFindings"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
        ]
        Resource = [
          aws_dynamodb_table.findings.arn,
          "${aws_dynamodb_table.findings.arn}/index/*",
        ]
      },
      {
        Sid    = "S3RemediationArtifacts"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
        ]
        Resource = "${aws_s3_bucket.remediation.arn}/*"
      },
      {
        Sid    = "SecurityHubPublish"
        Effect = "Allow"
        Action = [
          "securityhub:BatchImportFindings",
          "securityhub:BatchUpdateFindings",
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailLakeQuery"
        Effect = "Allow"
        Action = [
          "cloudtrail:StartQuery",
          "cloudtrail:GetQueryResults",
          "cloudtrail:DescribeQuery",
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = aws_cloudwatch_log_group.lambda_logs.arn
      },
      {
        Sid    = "SNSDigest"
        Effect = "Allow"
        Action = "sns:Publish"
        Resource = aws_sns_topic.weekly_digest.arn
      },
      {
        Sid    = "SQSDLQAccess"
        Effect = "Allow"
        Action = "sqs:SendMessage"
        Resource = aws_sqs_queue.lambda_dlq.arn
      },
      {
        Sid    = "KMSForEncryptedResources"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = aws_kms_key.analyzer.arn
      },
      {
        Sid    = "XRayTracing"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "scheduler" {
  name = "iam-analyzer-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "invoke-lambda"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.iam_analyzer.arn
    }]
  })
}
