# System Security Plan (SSP) — FedRAMP Low Baseline

## 1. Information System Name

GP-Copilot FedRAMP Compliance Demo (NovaPay Federal)

## 2. Information System Abbreviation

GP-FedRAMP-Demo

## 3. Information System Categorization

**FIPS 199 Impact Level**: Low

| Security Objective | Impact Level |
|-------------------|-------------|
| Confidentiality | Low |
| Integrity | Low |
| Availability | Low |

## 4. System Description

See `system-description.md`

## 5. Authorization Boundary

See `authorization-boundary.md`

## 6. System Environment

- **Deployment Model**: Kubernetes (EKS / k3s)
- **Service Model**: IaaS + PaaS (containerized workloads)
- **Cloud Provider**: AWS (production) / local k3s (demo)

## 7. System Interconnections

| Interconnected System | Direction | Agreement |
|----------------------|-----------|-----------|
| GitHub (CI/CD) | Bidirectional | GitHub TOS |
| Container Registry (ghcr.io) | Pull | GitHub TOS |
| NVD/GHSA (vuln databases) | Pull | Public API |

## 8. Control Implementation Summary

### Access Control (AC)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| AC-2 | Implemented | RBAC policies, SA auditing | `automation/kubernetes/rbac.yaml` |
| AC-3 | Implemented | K8s RBAC, namespace isolation | `automation/kubernetes/rbac.yaml` |
| AC-6 | Implemented | Pod security contexts, least-privilege | `automation/remediation/pod-security-context.yaml` |
| AC-17 | Implemented | API server access controls | `automation/kubernetes/rbac.yaml` |

See `../control-families/AC-access-control.md` for full details.

### Audit and Accountability (AU)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| AU-2 | Implemented | K8s audit logging, container logs | `automation/remediation/audit-logging.yaml` |
| AU-3 | Implemented | Structured audit log format | `automation/remediation/audit-logging.yaml` |

See `../control-families/AU-audit.md` for full details.

### Security Assessment and Authorization (CA)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| CA-2 | Implemented | Automated security assessment via JADE | `evidence/scan-reports/` |
| CA-7 | Implemented | Continuous monitoring via JSA-InfraSec | `.github/workflows/fedramp-compliance.yml` |

See `../control-families/CA-assessment.md` for full details.

### Configuration Management (CM)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| CM-2 | Implemented | Git-tracked manifests as baseline | `automation/kubernetes/` |
| CM-6 | Implemented | OPA/Gatekeeper + Kyverno policies | `automation/policies/` |
| CM-8 | Implemented | Kubernetes resource inventory | `automation/scanning/scan-and-map.py` |

See `../control-families/CM-config-mgmt.md` for full details.

### Identification and Authentication (IA)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| IA-5 | Implemented | Gitleaks secret detection, rotation | `automation/scanning/gitleaks.toml` |

See `../control-families/IA-identification.md` for full details.

### Risk Assessment (RA)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| RA-5 | Implemented | Trivy + Semgrep + Gitleaks scanning | `evidence/scan-reports/` |

See `../control-families/RA-risk-assessment.md` for full details.

### System and Communications Protection (SC)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| SC-7 | Implemented | NetworkPolicy default deny | `automation/kubernetes/networkpolicy.yaml` |
| SC-28 | Planned | Encryption at rest | — |

See `../control-families/SC-system-comms.md` for full details.

### System and Information Integrity (SI)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| SI-2 | Implemented | Container image scanning, patching | `automation/scanning/trivy-config.yaml` |

See `../control-families/SI-system-integrity.md` for full details.

## 9. Plan of Action and Milestones (POA&M)

See `../poam/`

## 10. Security Assessment Report (SAR)

See `../sar/`

## 11. Continuous Monitoring Plan

- **Automated Scanning**: GitHub Actions on every push (RA-5)
- **Runtime Monitoring**: JSA-InfraSec watchers with Falco (SI-4, CA-7)
- **Policy Enforcement**: OPA/Gatekeeper admission control (CM-6)
- **Evidence Generation**: Automated scan-to-NIST mapping (CA-2)
- **POA&M Updates**: Findings auto-populated from scan results

## 12. Revision History

| Date | Version | Description |
|------|---------|-------------|
| 2026-02-10 | 1.0 | Initial SSP creation |
