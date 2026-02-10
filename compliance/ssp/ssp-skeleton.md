# System Security Plan (SSP) — NovaPay Federal

## FedRAMP Low Baseline | NIST 800-53 Rev 5

## 1. Information System Name

NovaPay Federal Payroll Platform

## 2. Information System Abbreviation

NovaPay-FedRAMP

## 3. Information System Categorization

**FIPS 199 Impact Level**: Low

| Security Objective | Impact Level | Rationale |
|-------------------|-------------|-----------|
| Confidentiality | Low | Payroll data is sensitive but limited to individual agency scope |
| Integrity | Low | Financial data requires accuracy but transactions are reversible |
| Availability | Low | Payroll processing has scheduled windows, not real-time criticality |

## 4. System Description

See `system-description.md` for the full NovaPay Federal system description, including:
- Company profile (fintech, payroll for state/local governments, VA hospital contract)
- Technology stack (EKS, React, Python API, PostgreSQL, S3, GitHub Actions)
- Security automation architecture (Iron Legion platform)
- Data types processed and sensitivity levels
- Users and roles

## 5. Authorization Boundary

See `authorization-boundary.md`

The boundary encompasses NovaPay's EKS cluster, CI/CD pipeline, data stores, and the Iron Legion security automation platform.

## 6. System Environment

- **Deployment Model**: AWS EKS (production), k3s (assessment)
- **Service Model**: IaaS + PaaS (containerized workloads on AWS)
- **Cloud Provider**: AWS (us-east-1, us-west-2)
- **Container Runtime**: containerd on EKS-optimized AMIs
- **Policy Engine**: OPA/Gatekeeper + Kyverno (admission control)

## 7. System Interconnections

| Interconnected System | Direction | Agreement | Purpose |
|----------------------|-----------|-----------|---------|
| GitHub (CI/CD) | Bidirectional | GitHub TOS | Source control, automated scanning |
| Container Registry (ghcr.io) | Pull | GitHub TOS | Container image distribution |
| NVD/GHSA (vuln databases) | Pull | Public API | Vulnerability intelligence |
| AWS S3 | Bidirectional | AWS BAA | Document storage |
| AWS RDS (PostgreSQL) | Bidirectional | AWS BAA | Payroll database |

## 8. Control Implementation Summary

### Access Control (AC)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| AC-2 | Implemented | RBAC policies, service account auditing | `automation/kubernetes/rbac.yaml` |
| AC-3 | Implemented | K8s RBAC, namespace isolation | `automation/kubernetes/rbac.yaml` |
| AC-6 | Implemented | Pod security contexts, least-privilege containers | `automation/remediation/pod-security-context.yaml` |
| AC-17 | Implemented | API server access controls, audit logging | `automation/kubernetes/rbac.yaml` |

See `../control-families/AC-access-control.md` for full details.

### Audit and Accountability (AU)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| AU-2 | Implemented | K8s audit logging, Falco container monitoring | `automation/remediation/audit-logging.yaml` |
| AU-3 | Implemented | Structured audit log format with timestamp, user, action, resource | `automation/remediation/audit-logging.yaml` |

See `../control-families/AU-audit.md` for full details.

### Security Assessment and Authorization (CA)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| CA-2 | Implemented | Automated security assessment via JADE + multi-scanner pipeline | `evidence/scan-reports/` |
| CA-7 | Implemented | Continuous monitoring via JSA-InfraSec + GitHub Actions | `.github/workflows/fedramp-compliance.yml` |

See `../control-families/CA-assessment.md` for full details.

### Configuration Management (CM)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| CM-2 | Implemented | Git-tracked K8s manifests as configuration baseline | `automation/kubernetes/` |
| CM-6 | Implemented | OPA/Gatekeeper + Kyverno admission control | `automation/policies/` |
| CM-8 | Implemented | Trivy SBOM generation + Kubernetes API inventory | `automation/scanning/scan-and-map.py` |

See `../control-families/CM-config-mgmt.md` for full details.

### Identification and Authentication (IA)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| IA-5 | Implemented | Gitleaks secret detection, credential rotation procedures | `automation/scanning/gitleaks.toml` |

See `../control-families/IA-identification.md` for full details.

### Risk Assessment (RA)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| RA-5 | Implemented | Multi-scanner pipeline (Trivy, Semgrep, Gitleaks) + NIST mapping | `evidence/scan-reports/` |

See `../control-families/RA-risk-assessment.md` for full details.

### System and Communications Protection (SC)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| SC-7 | Implemented | Default deny NetworkPolicy, namespace segmentation | `automation/kubernetes/networkpolicy.yaml` |
| SC-28 | Planned | Encryption at rest via AWS KMS + EBS encryption | — |

See `../control-families/SC-system-comms.md` for full details.

### System and Information Integrity (SI)

| Control | Status | Implementation | Evidence |
|---------|--------|---------------|----------|
| SI-2 | Implemented | Container image scanning, automated patching pipeline | `automation/scanning/trivy-config.yaml` |

See `../control-families/SI-system-integrity.md` for full details.

## 9. Plan of Action and Milestones (POA&M)

See `../poam/` — All 35 initial findings have been remediated and verified.

## 10. Security Assessment Report (SAR)

See `../sar/sar-novapay.md` — Full assessment methodology, findings, and verification results.

## 11. Continuous Monitoring Plan

| Activity | Frequency | Tool | Control |
|----------|-----------|------|---------|
| Vulnerability scanning | Every code push | Trivy, Semgrep, Gitleaks | RA-5 |
| Runtime threat detection | Continuous | Falco, JSA-InfraSec | CA-7 |
| Admission policy enforcement | Every deployment | OPA/Gatekeeper, Kyverno | CM-6 |
| Evidence generation | Every code push | scan-and-map.py | CA-2 |
| POA&M updates | Automated from scan results | Iron Legion pipeline | SI-2 |
| Configuration drift detection | Continuous | JSA-InfraSec drift watcher | CM-2 |

## 12. Revision History

| Date | Version | Description |
|------|---------|-------------|
| 2026-02-10 | 1.0 | Initial SSP creation for NovaPay Federal engagement |
