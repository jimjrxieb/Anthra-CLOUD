# FedRAMP Compliance Demo — Step-by-Step Guide

This demo walks through the full FedRAMP compliance lifecycle using GP-Copilot's Iron Legion security platform against a real vulnerable web application (DVWA).

## The Scenario

**Client**: NovaPay Federal (fictional)
**Goal**: Achieve FedRAMP Low authorization for a cloud-based web application
**Our Approach**: Automated gap assessment, remediation, and evidence generation using the Iron Legion agent fleet

## Demo Flow

| Step | Guide | What You'll See |
|------|-------|----------------|
| 1 | [Target App Overview](01-target-app-overview.md) | DVWA: an intentionally vulnerable PHP app |
| 2 | [Pre-Deployment Scan](02-pre-deployment-scan.md) | Multi-scanner pipeline finds vulnerabilities |
| 3 | [Finding Classification](03-finding-classification.md) | Iron Legion rank system (E-S) categorizes risk |
| 4 | [NIST Control Mapping](04-nist-control-mapping.md) | Findings mapped to NIST 800-53 controls |
| 5 | [Automated Remediation](05-automated-remediation.md) | JSA agents auto-fix E-D rank findings |
| 6 | [Compliance Evidence](06-compliance-evidence.md) | SSP, POA&M, and SAR generated from real data |
| 7 | [Continuous Monitoring](07-continuous-monitoring.md) | GitHub Actions + runtime monitoring keep compliance |

## Quick Start

```bash
# 1. Run the target app
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

See [diagrams/iron-legion-fedramp.md](diagrams/iron-legion-fedramp.md) for the full architecture.
