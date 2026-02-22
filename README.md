# aws-iam-least-privilege-analyzer

> Continuous IAM policy analysis across AWS Organizations — risk scoring, privilege escalation detection, and least-privilege remediation using actual CloudTrail usage data.

[![CI](https://github.com/master-coder1998/aws-iam-least-privilege-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/master-coder1998/aws-iam-least-privilege-analyzer/actions/workflows/ci.yml)
[![Security Scan](https://github.com/master-coder1998/aws-iam-least-privilege-analyzer/actions/workflows/security.yml/badge.svg)](https://github.com/master-coder1998/aws-iam-least-privilege-analyzer/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## The Problem

In multi-account AWS environments, IAM drift is constant and invisible:

- Developers attach `AdministratorAccess` under deadline pressure and never remove it
- Role trust policies accumulate principals that no longer exist
- `iam:PassRole` combined with `lambda:CreateFunction` creates privilege escalation paths that no human reviewer catches
- AWS IAM Access Analyzer tells you about unused permissions — but only per-account, not at org scale, and without risk context
- CloudTrail tells you what was called — but not what *should* have been revoked months ago

This tool solves all of it in one automated, continuous pipeline.

---

## Architecture

```
AWS Organizations (all member accounts)
        │
        ▼
EventBridge Scheduler ──────────────────── daily @ 02:00 UTC
        │
        ▼
Lambda: IAM Crawler (cross-account role assumption)
  ├── Lists all IAM roles, users, policies per account
  ├── Pulls IAM Access Analyzer findings (unused permissions)
  ├── Queries CloudTrail Lake: actual API calls, last 90 days
  └── Resolves effective permissions (identity + resource + SCP + boundary)
        │
        ▼
Risk Scoring Engine (Python)
  ├── Wildcard action detection           → scores 0–30 pts
  ├── Wildcard resource detection         → scores 0–20 pts
  ├── Privilege escalation path analysis  → scores 0–40 pts (graph traversal)
  ├── Cross-account trust misconfiguration→ scores 0–30 pts
  ├── Admin role without MFA condition    → scores 0–25 pts
  ├── Stale role (90d+ unused)            → scores 0–15 pts
  └── Composite risk score (0–100) with severity tier
        │
        ▼
Remediation Generator
  ├── Computes least-privilege policy from actual CloudTrail usage
  ├── Generates policy diff (current vs. recommended)
  └── Stores remediation artifacts to S3
        │
        ├──▶ DynamoDB: findings store (history, delta, trend)
        ├──▶ Security Hub: custom findings (CRITICAL/HIGH/MEDIUM)
        ├──▶ S3: remediation policy JSON artifacts
        └──▶ SNS: weekly digest → security team email
```

### Multi-Account Trust Architecture

```
Management Account
  └── OrganizationSecurityRole (trust: management account)
        └── Assumes → MemberSecurityAuditRole (each member account)
              └── Permissions: ReadOnlyAccess + IAMReadOnlyAccess
                               + access-analyzer:List* + cloudtrail:*
```

All cross-account access uses **IAM roles with session tags** — no static credentials anywhere.

---

## Risk Scoring: How It Works

### Privilege Escalation Path Detection

The most important and least-understood part of this tool. AWS IAM has ~40+ known privilege escalation paths. This tool detects them via graph traversal:

```
Build permission graph:
  Node = IAM principal
  Edge = (action, resource) the principal can perform

Escalation detection:
  For each principal, check if any combination of their permissions
  allows them to reach AdministratorAccess through chained actions

Example paths detected:
  iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
  → Can create a Lambda with an admin role, invoke it, execute arbitrary AWS actions

  iam:CreatePolicyVersion
  → Can overwrite an existing policy with AdministratorAccess

  iam:AttachUserPolicy + iam:CreatePolicy
  → Can create an admin policy and attach it to themselves

  sts:AssumeRole (no condition) on a role with admin permissions
  → Lateral movement to admin context
```

See [`src/scoring/escalation_paths.py`](src/scoring/escalation_paths.py) for all 23 implemented paths with test cases.

### Why Access Analyzer Alone Is Insufficient

| Capability                    |   Access Analyzer   | This Tool |
|-------------------------------|---------------------|-----------|
| Unused permissions detection  |        ✅          |    ✅     |
| Org-wide aggregation          |  ❌ (per-account)  |    ✅     |
| Privilege escalation paths    |        ❌          |    ✅     |
| Risk scoring with context     |        ❌          |    ✅     |
| Least-privilege remediation   |        ❌          |    ✅     |
| SCP interaction analysis      |        ❌          |    ✅     |
| Historical drift tracking     |        ❌          |    ✅     |

Access Analyzer is a prerequisite (we consume its findings). It is not a replacement for this tool.

---

## Remediation: Least-Privilege Policy Generation

For each analyzed role, the tool generates a recommended policy based on **actual CloudTrail usage**:

```python
# Conceptual logic
actual_calls = cloudtrail_lake.query(
    principal=role_arn,
    lookback_days=90,
    group_by=["eventSource", "eventName", "resources"]
)

recommended_policy = Policy(
    statements=[
        Statement(
            effect="Allow",
            actions=[f"{call.service}:{call.action}" for call in actual_calls],
            resources=minimize_resources(actual_calls),  # least specific ARN that covers usage
        )
    ]
)
```

**Important caveats documented in remediation output:**
- Policy covers only the 90-day lookback window — seasonal or infrequent operations may be missing
- Resource ARNs are minimized but not perfectly scoped — review before applying
- The generated policy is a *starting point for human review*, not a push-button replacement
- Emergency break-glass scenarios may require broader permissions than 90-day usage shows

---

## Security Design Decisions

### ADR-001: Cross-Account Role Assumption via Organizations Trust

**Decision:** Use an Organizations-managed IAM role deployed to all member accounts via StackSets, rather than individual role deployments per account.

**Alternatives considered:**
- *Individual Terraform per account:* Doesn't scale to 50+ accounts, drift between accounts
- *AWS Config aggregator + Lambda:* Config doesn't capture all IAM metadata needed
- *AWS Security Hub custom actions:* Too limited for the data volume required

**Consequences:** Requires Organizations management account access. Acceptable trade-off given the security team already has this access for SCP management.

### ADR-002: CloudTrail Lake Over Standard CloudTrail S3

**Decision:** Query CloudTrail Lake for usage data rather than parsing S3-stored CloudTrail logs.

**Alternatives considered:**
- *Athena on S3 CloudTrail:* 10–20x higher cost for equivalent queries, much slower
- *CloudWatch Logs Insights:* Limited to 90-day retention, higher per-query cost at scale
- *Third-party SIEM:* Not universally available, adds external dependency

**Consequences:** Requires CloudTrail Lake to be enabled org-wide (additional cost ~$0.005/100K events). This cost is justified — the tool's value is zero without usage data.

### ADR-003: Risk Score Is Additive, Not Maximum

**Decision:** Risk score is the sum of all applicable risk factors (capped at 100), not the maximum single factor.

**Rationale:** A role with 5 medium risks is more concerning than a role with 1 high risk. Additive scoring reflects cumulative attack surface. Severity tier (CRITICAL/HIGH/MEDIUM/LOW) is derived from the composite score.

**Known limitation:** Additive scoring can over-penalize broad service roles (e.g., a data engineering role legitimately needs S3 wildcards on specific prefixes). The tool includes a `resource_scope_multiplier` that discounts wildcard penalties when resource ARNs are scoped to specific prefixes.

---

## Known Limitations

These are not bugs. They are documented design boundaries.

1. **SCP simulation is approximate.** Effective permission calculation for SCPs uses the IAM Policy Simulator API, which has known gaps with newer condition keys. For SCPs using `aws:PrincipalOrgID` with complex condition logic, manual verification is recommended.

2. **CloudTrail coverage is not 100%.** Some AWS services (notably older ones) do not log all API calls to CloudTrail. The generated least-privilege policy may miss calls from these services. The remediation output flags services with known CloudTrail gaps.

3. **Permission boundaries are evaluated but not simulated.** The tool detects whether a permission boundary is present and whether it is correctly scoped, but does not fully simulate boundary interactions with inline policies. Full simulation requires the IAM Policy Simulator, which is called for CRITICAL findings only (cost constraint).

4. **Federated sessions are partially tracked.** SAML/OIDC federated sessions appear in CloudTrail with the role ARN but session names vary. The tool groups by assumed role ARN, which may under-count or over-attribute usage in environments with many short-lived federated sessions.

5. **Resource-based policies are analyzed for S3, KMS, and Lambda only.** SQS, SNS, Secrets Manager, and other resource-based policy principals are not yet included in the cross-account analysis. This is the next planned capability.

---

## Deployment

### Prerequisites

- AWS Organizations with management account access
- Terraform >= 1.5
- CloudTrail Lake enabled org-wide
- IAM Access Analyzer enabled in all member accounts (org-level delegated admin recommended)

### Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/master-coder1998/aws-iam-least-privilege-analyzer
cd aws-iam-least-privilege-analyzer

# 2. Configure your org
cp terraform/environments/prod/terraform.tfvars.example \
   terraform/environments/prod/terraform.tfvars
# Edit: org_id, management_account_id, security_tooling_account_id,
#       notification_email, cloudtrail_lake_data_store_id

# 3. Deploy member account roles (via StackSets from management account)
cd terraform/modules/member-role
terraform init && terraform apply

# 4. Deploy the analyzer (in security tooling account)
cd terraform/environments/prod
terraform init && terraform apply

# 5. Trigger first run manually
aws lambda invoke \
  --function-name iam-analyzer-crawler \
  --payload '{"manual_trigger": true, "accounts": "all"}' \
  response.json
```

### Estimated AWS Cost

| Resource | Estimated Monthly Cost |
|---|---|
| Lambda invocations (daily) | ~$0.50 |
| CloudTrail Lake queries | ~$15–40 (depends on org size) |
| DynamoDB (on-demand) | ~$5–15 |
| Security Hub findings | ~$0.30/1000 findings |
| S3 (remediation artifacts) | ~$1–3 |
| **Total (50-account org)** | **~$25–65/month** |

---

## Running Tests

```bash
pip install -r requirements-dev.txt

# Unit tests
pytest tests/unit/ -v --cov=src --cov-report=term-missing

# Escalation path tests specifically
pytest tests/unit/test_escalation_paths.py -v

# Integration tests (requires AWS credentials with read access)
pytest tests/integration/ -v --aws-profile=security-audit
```

---

## Security Disclosure

Found a security issue in this tool? Please see [SECURITY.md](SECURITY.md).

Do not open a public GitHub issue for security vulnerabilities.

---

## License

MIT — see [LICENSE](LICENSE)
