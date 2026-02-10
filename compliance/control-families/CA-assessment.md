# CA — Security Assessment and Authorization

## CA-2: Security Assessments

**Requirement**: Develop a security assessment plan, assess security controls, produce a security assessment report, and remediate findings.

**Implementation**:
- **Assessment Plan**: Automated security scanning on every code push and on schedule
- **Assessment Execution**: Multi-tool scanning pipeline (Trivy, Semgrep, Gitleaks, Conftest)
- **Assessment Report**: JADE generates security reports with NIST 800-53 control mapping
- **Remediation**: JSA agents auto-fix E-D rank findings; JADE approves C-rank; B-S escalated to human

**Assessment Workflow**:
```
Code Push → GitHub Actions triggers scan pipeline
  → Trivy (container vulnerabilities, SI-2)
  → Semgrep (code vulnerabilities, RA-5)
  → Gitleaks (secret detection, IA-5)
  → Conftest (policy compliance, CM-6)
  → scan-and-map.py (NIST 800-53 mapping)
  → JADE classifies findings (E-S rank)
  → Auto-remediate (E-D) or escalate (B-S)
  → Generate evidence artifacts
```

**Evidence**:
- `evidence/scan-reports/` — Assessment results from initial and ongoing scans
- `.github/workflows/fedramp-compliance.yml` — Automated assessment pipeline
- `automation/scanning/scan-and-map.py` — NIST control mapping tool

**Iron Legion Mapping**:
- **JADE**: Primary owner — orchestrates assessments, classifies risk, generates reports
- **JSA-DevSec**: Executes pre-deployment scans
- **JSA-InfraSec**: Executes runtime assessments
- **Rank Classifier**: Maps findings to risk levels (RA-2 supporting CA-2)

---

## CA-7: Continuous Monitoring

**Requirement**: Develop a continuous monitoring strategy and implement a continuous monitoring program.

**Implementation**:
- **Ongoing Assessments**: GitHub Actions runs scans on every push and weekly schedule
- **Runtime Monitoring**: JSA-InfraSec watchers with Falco for syscall-level detection
- **Policy Enforcement**: OPA/Gatekeeper + Kyverno continuously enforce admission policies
- **Drift Detection**: JSA-InfraSec detects configuration drift from declared baseline
- **Status Reporting**: Scan results auto-mapped to NIST controls, POA&M updated

**Monitoring Frequency**:
| Activity | Frequency | Tool |
|----------|-----------|------|
| SAST scanning | Every push | Semgrep |
| Container scanning | Every push | Trivy |
| Secret detection | Every push | Gitleaks |
| Policy validation | Every push | Conftest |
| Runtime threat detection | Continuous | Falco |
| Admission enforcement | Continuous | OPA/Kyverno |
| Drift detection | Hourly | JSA-InfraSec |
| NIST control mapping | Every push | scan-and-map.py |

**Evidence**:
- `.github/workflows/fedramp-compliance.yml` — CI/CD continuous monitoring
- `automation/policies/` — Policy-as-code enforcement
- `evidence/scan-reports/` — Historical evidence trail
