# Step 2: Pre-Deployment Security Scan

## JSA-DevSec Scanner Pipeline

Before any code reaches the cluster, JSA-DevSec runs a multi-tool scanning pipeline. This maps to **FedRAMP RA-5 (Vulnerability Scanning)**.

## Running the Scan

```bash
# Full scan with NIST control mapping
python automation/scanning/scan-and-map.py --target-dir target-app

# Or run individual scanners:
trivy fs target-app/ --format json
semgrep --config automation/scanning/semgrep-rules.yaml target-app/
gitleaks detect --source target-app/ --config automation/scanning/gitleaks.toml
```

## Scanner Coverage

| Scanner | What It Checks | FedRAMP Control |
|---------|---------------|----------------|
| **Trivy** | Container images, OS packages, dependencies | SI-2 |
| **Semgrep** | Source code vulnerabilities (SQLi, XSS, etc.) | RA-5 |
| **Gitleaks** | Hardcoded secrets, API keys, credentials | IA-5 |
| **Conftest** | Kubernetes manifest policy compliance | CM-6 |

## Scan Results (DVWA)

From our initial assessment:

| Scanner | Findings | Details |
|---------|----------|---------|
| Bandit (Python) | 2 | Missing timeout, assert statement |
| Semgrep | 0 | Clean after auto-fix |
| Trivy | 0 | No CVEs in dependencies |
| JSA-DevSec (aggregate) | 33 files | SQL injection, XSS, command injection, CSRF |

Full results: `evidence/scan-reports/`

## What Happens Next

Each finding gets classified by the Iron Legion rank system. See [Step 3: Finding Classification](03-finding-classification.md).
