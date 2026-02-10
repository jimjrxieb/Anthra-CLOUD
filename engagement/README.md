# NovaPay Federal Engagement Walkthrough

This walkthrough takes you through the complete NovaPay Federal FedRAMP engagement — from initial client assessment through continuous compliance — using GP-Copilot's Iron Legion security platform.

## The Scenario

**Client**: NovaPay Federal — fintech, payroll & financial management
**Problem**: Won a VA hospital payroll contract, needs FedRAMP Low authorization
**Stack**: EKS, React, Python API, PostgreSQL, S3, GitHub Actions
**Starting point**: No compliance program, no NIST controls, no vulnerability management

## Engagement Flow

| Step | Guide | What You'll See |
|------|-------|----------------|
| 1 | [Client Assessment](01-client-assessment.md) | NovaPay's application and its vulnerability surface |
| 2 | [Gap Analysis](02-gap-analysis.md) | Multi-scanner pipeline finds security gaps |
| 3 | [Risk Classification](03-risk-classification.md) | Iron Legion rank system (E-S) categorizes risk |
| 4 | [Control Mapping](04-control-mapping.md) | Findings mapped to NIST 800-53 controls |
| 5 | [Automated Remediation](05-automated-remediation.md) | JSA agents auto-fix E-D rank findings |
| 6 | [Evidence Generation](06-evidence-generation.md) | SSP, POA&M, SAR generated from real scan data |
| 7 | [Continuous Compliance](07-continuous-compliance.md) | GitHub Actions + runtime monitoring for ongoing compliance |

## Quick Start

```bash
# 1. Run NovaPay's application
cd target-app && docker compose up -d

# 2. Run the security scan pipeline
python automation/scanning/scan-and-map.py --target-dir target-app

# 3. Validate Kubernetes policies
conftest test automation/kubernetes/ --policy automation/policies/conftest/

# 4. View compliance artifacts
ls compliance/
ls evidence/
```

## Architecture

See [ARCHITECTURE.md](../ARCHITECTURE.md) for the full Iron Legion → FedRAMP control mapping.
