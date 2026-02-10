# RA — Risk Assessment

## RA-5: Vulnerability Monitoring and Scanning

**Requirement**: Scan for vulnerabilities in the information system and hosted applications, and remediate legitimate vulnerabilities in accordance with risk assessments.

**Implementation**:
- **Container Scanning**: Trivy scans container images for known CVEs (OS packages + application deps)
- **Static Analysis**: Semgrep performs SAST on application source code (PHP, Python, JavaScript)
- **Secret Detection**: Gitleaks identifies leaked credentials
- **Dependency Scanning**: Trivy + Grype check dependency manifests (composer.json, requirements.txt)
- **Policy Compliance**: Conftest validates Kubernetes manifests against OPA policies
- **Risk Classification**: Iron Legion rank system (E-S) categorizes findings by severity and remediation complexity

**Scanning Pipeline**:
```
Source Code → Semgrep (SAST) → Code vulnerabilities
           → Gitleaks → Credential exposure
Container  → Trivy → CVEs, misconfigurations
Manifests  → Conftest → Policy violations
All        → scan-and-map.py → NIST 800-53 mapping
           → Rank Classifier → E-S risk categorization
```

**Scan Results (DVWA Target App)**:
| Scanner | Findings | Remediated | Evidence |
|---------|----------|-----------|----------|
| Bandit (Python) | 2 | 2 (100%) | `evidence/scan-reports/initial-scan.json` |
| Semgrep | 0 | N/A | `evidence/scan-reports/semgrep-scan.json` |
| Trivy | 0 | N/A | `evidence/scan-reports/trivy-scan.json` |
| Verification | 0 | N/A | `evidence/scan-reports/verification-scan.json` |

**Vulnerability Classification (Iron Legion Ranks)**:
| Rank | CVSS Equivalent | Remediation | SLA |
|------|----------------|-------------|-----|
| E | Informational | Auto-fix, no approval | Immediate |
| D | Low-Medium | Auto-fix, logged | < 24 hours |
| C | Medium-High | JADE approves fix | < 72 hours |
| B | High-Critical | Human review required | < 7 days |
| S | Critical/Strategic | Human-only decision | Risk-based |

**Evidence**:
- `evidence/scan-reports/` — All scan results
- `evidence/remediation/SECURITY_REMEDIATION.md` — Remediation report (33 files fixed)
- `automation/scanning/` — Scanner configurations
- `.github/workflows/fedramp-compliance.yml` — Automated scanning pipeline

**Iron Legion Mapping**:
- **JSA-DevSec**: Primary scanner operator — runs Trivy, Semgrep, Gitleaks, Conftest
- **JADE**: Classifies findings to ranks, maps to NIST controls
- **Rank Classifier**: ML-based risk categorization (supports RA-2)
