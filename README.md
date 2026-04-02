# IAM Accelerator

A production-ready **Multi-Cloud IAM Strategy Accelerator** that audits, scores, and remediates IAM risk across **AWS** and **Azure** — with zero real cloud credentials needed for a full demo run.

---

## Purpose

Organizations running workloads across AWS and Azure accumulate IAM debt quickly: overprivileged users, stale credentials, missing MFA, and wildcard policies. This tool provides:

- **Automated auditing** of IAM users, roles, policies, and service accounts
- **Risk scoring** (0–100 per resource, plus overall environment risk level)
- **Permission mapping** (who → what → how, exportable as Graphviz DOT)
- **Prioritized remediation plan** with ready-to-paste CLI commands
- **Self-contained HTML executive report** (no CDN dependencies)

---

## Quickstart (no real cloud credentials needed)

```bash
# 1. Clone and install
git clone <repo-url>
cd iam-accelerator
pip install -e ".[dev]"

# 2. Run the demo against bundled sample data
python -c "
from auditors import AWSAuditor
from analyzers import RiskScorer, PermissionMapper, RemediationPlanner
from reporters import ExecutiveReportGenerator
from pathlib import Path

auditor  = AWSAuditor(account_id='123456789012', sample_data_path='data/samples/aws_iam_sample.json')
result   = auditor.run()
report   = RiskScorer().score(result)
plan     = RemediationPlanner().plan(report)
html, js = ExecutiveReportGenerator(output_dir='output').generate(result, report, plan)
print('Report written to:', html)
"

# 3. Open output/iam_report.html in your browser
```

---

## Running Tests

```bash
pytest --cov --cov-report=term-missing
```

Expected: **≥ 80% coverage**, all tests pass.

---

## Risk Scoring Methodology

Each IAM resource (user, role, service account) receives a risk score from **0 to 100** based on weighted factors:

| Risk Factor | Weight | Condition |
|---|---|---|
| Wildcard action (`*`) | 35 | Any attached/inline policy allows `Action: *` |
| Broad named policy | 20 | AdministratorAccess, Owner, PowerUserAccess, etc. |
| Cross-account trust | 20 | Role trust policy references an external account |
| Public role | 30 | Trust policy principal is `*` |
| Wildcard resource | 15 | Policy applies to `Resource: *` |
| Stale credential | 15 | Last activity > 90 days ago |
| Missing MFA | 10 | No MFA device registered |
| Stale access key | 15 | Active key unused for > 90 days |

**Score → Risk Level:**

| Score | Level |
|---|---|
| 75–100 | CRITICAL |
| 50–74 | HIGH |
| 25–49 | MEDIUM |
| 0–24 | LOW |

---

## Using Real Cloud Credentials

### AWS

```python
import boto3
from auditors import AWSAuditor

client = boto3.client("iam", region_name="us-east-1")
auditor = AWSAuditor(account_id="123456789012", boto3_client=client)
result = auditor.run()
```

The Terraform module in `terraform/aws/` creates a least-privilege IAM role with read-only IAM permissions that you can assume.

### Azure

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from auditors import AzureAuditor

# AzureAuditor accepts the raw sample_data_path for offline use, or
# you can extend it to pass a live auth_client.
auditor = AzureAuditor(
    subscription_id="<your-subscription-id>",
    sample_data_path="data/samples/azure_rbac_sample.json",  # replace with live data
)
result = auditor.run()
```

---

## Terraform Deployment

### AWS — Auditor Role

```bash
cd terraform/aws
terraform init
terraform apply -var='trusted_principal_arns=["arn:aws:iam::YOUR_ACCOUNT:role/YOUR_ROLE"]'
```

Output: `auditor_role_arn` — use this ARN to assume the read-only auditor role.

### Azure — Custom Reader Role

```bash
cd terraform/azure
terraform init
terraform apply \
  -var='subscription_id=<SUB_ID>' \
  -var='resource_group_name=<RG_NAME>' \
  -var='auditor_principal_id=<SP_OBJECT_ID>'
```

Output: `role_definition_id` — the custom least-privilege reader role scoped to the resource group.

---

## Project Structure

```
iam-accelerator/
├── auditors/           # Cloud-specific IAM auditors (AWS, Azure) + base class
├── analyzers/          # Risk scorer, permission mapper, remediation planner
├── reporters/          # HTML + JSON executive report generator
├── terraform/          # AWS and Azure Terraform modules
├── tests/              # pytest test suite (≥80% coverage)
├── data/samples/       # Realistic mock IAM data for offline demos
└── pyproject.toml
```
