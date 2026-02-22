variable "aws_region" {
  description = "AWS region for the analyzer deployment"
  type        = string
  default     = "us-east-1"
}

variable "org_id" {
  description = "AWS Organizations ID (e.g. o-xxxxxxxxxx)"
  type        = string
}

variable "org_account_id" {
  description = "AWS Organizations management account ID"
  type        = string
}

variable "cloudtrail_lake_data_store_id" {
  description = "CloudTrail Lake event data store ARN or ID"
  type        = string
}

variable "security_account_id" {
  description = "Security tooling account ID (where this module is deployed)"
  type        = string
}

variable "remediation_bucket_prefix" {
  description = "Prefix for the S3 remediation artifacts bucket name"
  type        = string
  default     = "iam-analyzer-remediation"
}

variable "notification_email" {
  description = "Email address for weekly security digest"
  type        = string
}

variable "min_severity_for_sechub" {
  description = "Minimum severity to publish to Security Hub (LOW/MEDIUM/HIGH/CRITICAL)"
  type        = string
  default     = "MEDIUM"

  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH", "CRITICAL"], var.min_severity_for_sechub)
    error_message = "min_severity_for_sechub must be LOW, MEDIUM, HIGH, or CRITICAL."
  }
}

variable "cross_account_external_id" {
  description = "ExternalId for cross-account role assumption (set in member account roles)"
  type        = string
  sensitive   = true
  default     = null
}
