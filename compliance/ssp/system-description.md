# System Description

## System Name

GP-Copilot FedRAMP Compliance Demo

## System Overview

This system demonstrates automated FedRAMP compliance using the Iron Legion security platform (GP-Copilot) against a target web application (DVWA). The platform automates vulnerability detection, risk classification, remediation, and continuous compliance monitoring mapped to NIST 800-53 Rev 5 controls.

## System Components

### Target Application (DVWA)
- **Type**: PHP/MySQL web application
- **Purpose**: Intentionally vulnerable application serving as the assessment target
- **Runtime**: Docker container (PHP 8 + Apache)
- **Database**: MariaDB 10
- **Network**: Isolated via Kubernetes NetworkPolicy / Docker network

### Security Automation (GP-Copilot / Iron Legion)
- **JSA-DevSec**: Pre-deployment security scanning (Trivy, Semgrep, Gitleaks, Checkov, etc.)
- **JSA-InfraSec**: Runtime security monitoring (Falco, Kyverno, NetworkPolicy enforcement)
- **JADE AI**: C-rank supervisor — approves findings, maps to NIST controls, generates evidence
- **Rank Classifier**: ML-based risk classification (E-S scale mapped to RA-2)

### Infrastructure
- **Container Orchestration**: Kubernetes (k3s / EKS)
- **Policy Enforcement**: OPA/Gatekeeper, Kyverno, Pod Security Standards
- **Monitoring**: Prometheus metrics, Falco alerts, audit logging
- **CI/CD**: GitHub Actions with integrated security scanning

## Data Flow

```
Developer Push → GitHub Actions (JSA-DevSec scans) → Findings
    → Rank Classifier (E-S) → JADE Approval (C-rank ceiling)
    → Automated Remediation (E-D) or Human Escalation (B-S)
    → Evidence Generation → NIST 800-53 Control Mapping
    → POA&M Update → Continuous Monitoring Dashboard
```

## Users and Roles

| Role | Access Level | Corresponds To |
|------|-------------|----------------|
| System Owner | Full admin | S-rank (human only) |
| Security Engineer | Operate + configure | B-rank (human + JADE) |
| JADE AI Supervisor | Approve E-C findings | C-rank ceiling |
| JSA Agents | Execute scans/fixes | E-C rank automation |
| Auditor | Read-only evidence | Read access to compliance/ |

## Authorization Boundary

See `authorization-boundary.md` for the full boundary diagram.
