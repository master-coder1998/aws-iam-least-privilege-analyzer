# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| main branch | ✅ |
| Tagged releases | ✅ |
| Older branches | ❌ |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you've found a security vulnerability in this tool — including issues with the IAM role configurations, privilege escalation detection logic, or the Terraform modules — please report it privately.

### How to Report

LinkedIn: https://www.linkedin.com/in/ankita-dixit-8892b8185/  
Git: https://github.com/master-coder1998

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix (if any)

### What to Expect

- **Acknowledgement** within 48 hours
- **Initial assessment** within 5 business days
- **Fix timeline** communicated within 10 business days
- **Credit** in the release notes (if desired)

### Scope

This project is a security tool. Vulnerabilities that are particularly concerning include:

- The cross-account IAM role trust policy being exploitable for privilege escalation
- The Lambda execution role having more permissions than documented
- The S3 remediation bucket being accessible from outside the organization
- Any hardcoded credentials or secrets in the codebase or Terraform
- Logic errors in escalation path detection that produce false negatives
  (i.e., the tool misses real escalation paths)

### Out of Scope

- Issues requiring physical access to infrastructure
- Social engineering
- DoS attacks against the Lambda

## Security Design Notes

For security researchers reviewing this codebase:

1. **Cross-account access** uses an ExternalId condition to prevent confused deputy attacks (see `terraform/modules/member-role/main.tf`)
2. **No static credentials** anywhere in the codebase — all authentication via IAM roles
3. **Remediation artifacts** are stored in S3 with organization-scoped bucket policy — no cross-account reads
4. **Security Hub findings** use deterministic IDs to prevent duplicate finding injection
5. **Lambda execution role** follows least-privilege — see the explicit action list in `terraform/environments/prod/main.tf`
