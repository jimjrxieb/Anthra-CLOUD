# System Description — NovaPay Federal

## System Name

NovaPay Federal Payroll Platform

## System Owner

NovaPay Federal — fintech company specializing in payroll and financial management for state and local governments.

## System Overview

NovaPay Federal's payroll platform processes payroll and financial management data for government agencies, including a recently awarded VA hospital system contract. The platform runs on AWS EKS with a React frontend, Python API backend, PostgreSQL database, and S3 for document storage. CI/CD is managed through GitHub Actions.

This system underwent a FedRAMP Low authorization engagement using the GP-Copilot Iron Legion security platform. The engagement took NovaPay from zero compliance (no NIST controls, no vulnerability management, no security documentation) to audit-ready in 6 weeks.

For this engagement, DVWA (Damn Vulnerable Web Application) serves as a simplified stand-in for NovaPay's proprietary application. DVWA provides realistic vulnerabilities — SQL injection, XSS, command injection, hardcoded credentials — that map directly to the kinds of findings encountered in real-world assessments.

## System Components

### NovaPay Application (represented by DVWA)
- **Type**: PHP/MySQL web application (DVWA stands in for NovaPay's React + Python stack)
- **Purpose**: Payroll processing and financial management for government agencies
- **Runtime**: Docker container (PHP 8 + Apache)
- **Database**: MariaDB 10 (stands in for PostgreSQL)
- **Network**: Isolated via Kubernetes NetworkPolicy / Docker network

### Security Automation (GP-Copilot / Iron Legion)
- **JSA-DevSec**: Pre-deployment security scanning (Trivy, Semgrep, Gitleaks, Checkov, Conftest)
- **JSA-InfraSec**: Runtime security monitoring (Falco, Kyverno, NetworkPolicy enforcement)
- **JADE AI**: C-rank supervisor — approves findings, maps to NIST controls, generates evidence
- **Rank Classifier**: ML-based risk classification (E-S scale mapped to RA-2)

### Infrastructure
- **Container Orchestration**: AWS EKS (production) / k3s (assessment environment)
- **Policy Enforcement**: OPA/Gatekeeper, Kyverno, Pod Security Standards
- **Monitoring**: Prometheus metrics, Falco alerts, audit logging
- **CI/CD**: GitHub Actions with integrated security scanning on every push

## Data Flow

```
Developer Push → GitHub Actions (JSA-DevSec scans) → Findings
    → Rank Classifier (E-S) → JADE Approval (C-rank ceiling)
    → Automated Remediation (E-D) or Human Escalation (B-S)
    → Evidence Generation → NIST 800-53 Control Mapping
    → POA&M Update → Continuous Monitoring Dashboard
```

## Data Types Processed

| Data Category | Sensitivity | FedRAMP Relevance |
|--------------|-------------|-------------------|
| Payroll records | PII — employee names, SSNs, bank accounts | Confidentiality (SC-28) |
| Financial transactions | Sensitive — payment amounts, tax withholdings | Integrity (SI-2) |
| Government agency data | CUI — agency identifiers, contract details | Access Control (AC-2, AC-3) |
| Authentication credentials | Sensitive — user passwords, API keys | IA-5 |
| Audit logs | Internal — system events, access records | AU-2, AU-3 |

## Users and Roles

| Role | Access Level | Corresponds To |
|------|-------------|----------------|
| System Owner (NovaPay CISO) | Full admin | S-rank (human only) |
| Security Engineer | Operate + configure | B-rank (human + JADE) |
| JADE AI Supervisor | Approve E-C findings | C-rank ceiling |
| JSA Agents | Execute scans/fixes | E-C rank automation |
| 3PAO Auditor | Read-only evidence | Read access to compliance/ and evidence/ |
| NovaPay Developers | Code push | Triggers CI/CD scanning pipeline |

## Authorization Boundary

The authorization boundary encompasses:
- NovaPay's application containers (EKS pods)
- Kubernetes cluster infrastructure (EKS control plane + worker nodes)
- CI/CD pipeline (GitHub Actions runners)
- Security automation agents (JSA-DevSec, JSA-InfraSec, JADE)
- Data stores (PostgreSQL/RDS, S3 buckets)
- Monitoring and logging infrastructure

See `authorization-boundary.md` for the full boundary diagram.
