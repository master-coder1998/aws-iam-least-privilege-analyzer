# Remediation Runbook: IAM Over-Privileged Role

**Audience:** Security engineers, cloud platform engineers  
**Triggered by:** Security Hub finding — `IAM Role Over-Privileged`  
**Severity scope:** MEDIUM, HIGH, CRITICAL

---

## Triage (First 15 minutes)

### Step 1 — Understand the finding

Open the Security Hub finding and note:
- **Composite score** (0–100): determines urgency
- **Escalation paths detected**: IDs like ESC-002, ESC-007 — look these up in `src/scoring/escalation_paths.py`
- **Score breakdown**: which dimensions contributed (wildcard actions, trust policy, staleness, etc.)
- **Role ARN and account ID**

### Step 2 — Is this role actively used?

```bash
# Check DynamoDB for recent usage data
aws dynamodb query \
  --table-name iam-analyzer-findings \
  --key-condition-expression "pk = :pk AND begins_with(sk, :sk)" \
  --expression-attribute-values '{":pk": {"S": "ROLE#<ACCOUNT_ID>#<ROLE_ARN>"}, ":sk": {"S": "SCORE#"}}' \
  --region us-east-1 | jq '.Items[-1]'

# Check CloudTrail for recent API calls from this role (last 7 days)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="<role-name>" \
  --start-time $(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 20
```

### Step 3 — Who owns this role?

```bash
# Check role tags for team ownership
aws iam get-role --role-name <role-name> \
  --query 'Role.Tags[?Key==`Team` || Key==`Owner` || Key==`Service`]'
```

If no ownership tags: search your service catalog or ask in #cloud-security Slack channel.

---

## Severity-Specific Response

### CRITICAL (score ≥ 70)

**Target remediation time: 48 hours**

1. Immediately notify the role owner (ticket + Slack DM)
2. If escalation paths detected (ESC-001 through ESC-023):
   - Check CloudTrail for any suspicious exploitation attempts
   - Search for: `CreatePolicyVersion`, `AttachUserPolicy`, `UpdateFunctionCode` events from this role
3. Apply the auto-generated least-privilege policy (see S3 artifacts below) after owner review
4. If role is unused (staleness score > 0): schedule deletion within 48h
5. Escalate to security lead if the role has ever been assumed by an external account

### HIGH (score 45–69)

**Target remediation time: 1 week**

1. Open ticket with role owner team
2. Review the top 3 escalation paths in the finding
3. Apply the least-privilege policy from S3 remediation artifacts
4. If wildcard actions are present: replace with specific action list
5. If cross-account trust without ExternalId: add ExternalId condition

### MEDIUM (score 20–44)

**Target remediation time: 2 weeks**

1. Open ticket for next sprint
2. Document findings in the role's team wiki
3. Apply least-privilege policy at next planned change window

---

## Applying the Remediation Policy

### Step 1 — Retrieve the artifact

```bash
# List available remediation artifacts for this role
aws s3 ls "s3://<bucket>/remediation/<account-id>/<role-name>/"

# Download the most recent
aws s3 cp \
  "s3://<bucket>/remediation/<account-id>/<role-name>/<date>.json" \
  /tmp/remediation.json

# Review the policy
cat /tmp/remediation.json | jq '.recommended_policy'
cat /tmp/remediation.json | jq '.metadata.caveats'
cat /tmp/remediation.json | jq '.metadata.coverage_warnings'
```

### Step 2 — Review before applying

**Always review these before applying any auto-generated policy:**

- [ ] Do the actions cover all workloads running with this role?
- [ ] Are there infrequent operations (monthly jobs, quarterly audits) that wouldn't appear in the 90-day window?
- [ ] Are there CloudTrail coverage warnings (SQS, SNS, Kinesis)?
- [ ] Does the policy include permissions for disaster recovery scenarios?
- [ ] Check with the role owner: are there any planned future actions this role will need?

### Step 3 — Apply as a new managed policy (preferred over inline)

```bash
# Create the new least-privilege policy
aws iam create-policy \
  --policy-name "<role-name>-least-privilege-$(date +%Y%m%d)" \
  --policy-document file:///tmp/policy.json \
  --description "Auto-generated least-privilege policy from IAM Analyzer ($(date +%Y-%m-%d))"

# Attach new policy to role
aws iam attach-role-policy \
  --role-name <role-name> \
  --policy-arn <new-policy-arn>

# WAIT and monitor for 24-48 hours before removing old policies
# Watch for AccessDenied errors in CloudWatch Logs and CloudTrail
```

### Step 4 — Remove old overly-permissive policies

Only after confirming the new policy works:

```bash
# Detach the old broad policy
aws iam detach-role-policy \
  --role-name <role-name> \
  --policy-arn <old-policy-arn>
```

---

## Cross-Account Trust Remediation

If the finding includes a trust policy issue (score from `cross_account_trust` dimension):

### Missing ExternalId (confused deputy vulnerability)

```json
// Add to the trust policy Condition block:
"Condition": {
  "StringEquals": {
    "sts:ExternalId": "<generate-a-uuid>"
  }
}
```

Coordinate the ExternalId value with the external account that assumes this role.

### Wildcard Principal in trust policy

```bash
# This is a CRITICAL misconfiguration — role can be assumed by anyone
# Immediately replace with the specific principal ARN(s) that should have access
aws iam update-assume-role-policy \
  --role-name <role-name> \
  --policy-document file:///tmp/corrected-trust-policy.json
```

---

## False Positive Process

If you believe this finding is a false positive or an accepted risk:

1. Add a suppression in Security Hub with justification:
   - Go to Security Hub → Findings → Find the finding → Actions → Suppress
   - Required suppression note format: `[ACCEPTED-RISK] Reason: <business justification> | Owner: <team> | Review date: <YYYY-MM-DD>`

2. Log the exception in the risk register (Confluence: Cloud Security / Risk Exceptions)

3. Set a calendar reminder for the review date — suppressions should not be permanent

4. The analyzer will automatically re-surface the finding if the score increases.

---

## Escalation Path Quick Reference

| Path ID | Name | Minimum actions to remediate |
|---|---|---|
| ESC-001 | CreatePolicyVersion | Remove `iam:CreatePolicyVersion` or restrict to specific policy ARNs |
| ESC-002 | PassRole+Lambda | Restrict `iam:PassRole` to specific role ARNs; add `iam:PassedToService` condition |
| ESC-003 | PassRole+EC2 | Restrict `iam:PassRole` + add IMDSv2 enforcement |
| ESC-007 | PutRolePolicy | Remove `iam:PutRolePolicy` entirely or restrict via SCP |
| ESC-017 | STSAssumeRole wildcard | Scope `sts:AssumeRole` resource to specific role ARNs |
| ESC-021 | UpdateFunctionCode | Restrict to specific function ARNs; require code signing |

For full remediation guidance for all 23 paths, see `src/scoring/escalation_paths.py`.

---

## Metrics Tracking

After remediation:
- Update the Security Hub finding status to `RESOLVED`
- The next analyzer run (within 24h) will re-score the role
- If the score drops below the publishing threshold, the finding is auto-resolved
- Track remediation time in the security team's SLA dashboard
