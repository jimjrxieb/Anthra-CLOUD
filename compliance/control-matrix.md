# FedRAMP Control Matrix

Maps NIST 800-53 Rev 5 controls to Iron Legion tools, automation, and evidence.

## Legend

- **Status**: Implemented / Partially / Planned
- **Automation**: E (full auto) / D (auto + logging) / C (JADE approves) / B (human required)
- **Tool**: Primary tool implementing the control
- **Agent**: Iron Legion agent responsible

## Control × Tool × Evidence × Rank Matrix

| Control | Name | Status | Tool(s) | Agent | Rank | Evidence Path |
|---------|------|--------|---------|-------|------|---------------|
| **AC-2** | Account Management | Implemented | RBAC audit | JSA-InfraSec | D | `automation/kubernetes/rbac.yaml` |
| **AC-3** | Access Enforcement | Implemented | K8s RBAC, OPA | JSA-DevSec + InfraSec | D | `automation/kubernetes/rbac.yaml` |
| **AC-6** | Least Privilege | Implemented | PSS, Kyverno | JSA-DevSec | E | `automation/remediation/pod-security-context.yaml` |
| **AC-17** | Remote Access | Implemented | K8s audit log | JSA-InfraSec | C | `automation/remediation/audit-logging.yaml` |
| **AU-2** | Audit Events | Implemented | K8s audit, Falco | JSA-InfraSec | D | `automation/remediation/audit-logging.yaml` |
| **AU-3** | Audit Record Content | Implemented | K8s audit policy | JSA-InfraSec | D | `automation/remediation/audit-logging.yaml` |
| **CA-2** | Security Assessments | Implemented | Multi-scanner pipeline | JADE | C | `evidence/scan-reports/` |
| **CA-7** | Continuous Monitoring | Implemented | GHA + Falco + Kyverno | All agents | D | `.github/workflows/fedramp-compliance.yml` |
| **CM-2** | Baseline Configuration | Implemented | Git + IaC | JSA-DevSec | D | `automation/kubernetes/` |
| **CM-6** | Configuration Settings | Implemented | OPA/Kyverno/Conftest | JSA-DevSec | D | `automation/policies/` |
| **CM-8** | Component Inventory | Implemented | Trivy SBOM + K8s API | JSA-DevSec | E | `automation/scanning/scan-and-map.py` |
| **IA-5** | Authenticator Management | Implemented | Gitleaks | JSA-DevSec | E-B* | `automation/scanning/gitleaks.toml` |
| **RA-5** | Vulnerability Scanning | Implemented | Trivy + Semgrep + Gitleaks | JSA-DevSec | D | `evidence/scan-reports/` |
| **SC-7** | Boundary Protection | Implemented | NetworkPolicy | JSA-InfraSec | D | `automation/kubernetes/networkpolicy.yaml` |
| **SC-28** | Info at Rest | Planned | EBS/etcd encryption | Infrastructure | B | — |
| **SI-2** | Flaw Remediation | Implemented | Trivy + auto-patch | JSA-DevSec | D | `evidence/remediation/SECURITY_REMEDIATION.md` |

*IA-5: E-rank for detection, B-rank for credential exposure response.

## Agent Responsibility Summary

| Agent | Primary Controls | Role |
|-------|-----------------|------|
| **JSA-DevSec** | RA-5, SI-2, CM-6, IA-5, AC-6 | Pre-deployment scanning and remediation |
| **JSA-InfraSec** | CA-7, SC-7, AU-2, AU-3, AC-2, AC-3 | Runtime monitoring and enforcement |
| **JADE** | CA-2, RA-2 | Risk classification, evidence generation, approval |
| **Rank Classifier** | RA-2 (supporting) | ML-based risk categorization E→S |

## Coverage Summary

| Metric | Value |
|--------|-------|
| Total FedRAMP Low controls | 125 |
| Controls fully documented | 15 |
| Controls with automation | 15 |
| Controls with evidence | 14 |
| Controls planned | 1 (SC-28) |
