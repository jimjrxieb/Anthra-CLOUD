# Architecture: NovaPay Federal FedRAMP Engagement

How the Iron Legion security platform was applied to NovaPay Federal's application to achieve FedRAMP Low compliance against NIST 800-53 Rev 5 controls.

## Iron Legion → NovaPay Mapping

| Iron Legion Component | FedRAMP Role | Primary Controls |
|----------------------|-------------|-----------------|
| **JSA-DevSec** | Pre-deployment scanner | RA-5 (Vulnerability Scanning) |
| **JSA-InfraSec** | Runtime monitor | CA-7 (Continuous Monitoring) |
| **JADE AI** | Security assessor | CA-2 (Security Assessments) |
| **Rank Classifier** | Risk categorizer | RA-2 (Risk Categorization) |

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    FedRAMP COMPLIANCE PIPELINE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SOURCE CODE                                                     │
│       │                                                          │
│       ▼                                                          │
│  ┌──────────────────────────────────────────┐                   │
│  │         JSA-DEVSEC (RA-5, SI-2)          │                   │
│  │  Trivy · Semgrep · Gitleaks · Conftest   │                   │
│  │  "Is this safe to deploy?"               │                   │
│  └──────────────────┬───────────────────────┘                   │
│                     │ findings                                   │
│                     ▼                                            │
│  ┌──────────────────────────────────────────┐                   │
│  │       RANK CLASSIFIER (RA-2)             │                   │
│  │  E (auto) · D (auto+log) · C (JADE)     │                   │
│  │  B (human) · S (executive)               │                   │
│  └──────────┬───────────┬───────────────────┘                   │
│             │           │                                        │
│        E-D rank    C rank     B-S rank                          │
│             │           │         │                              │
│             ▼           ▼         ▼                              │
│        JSA auto    JADE (CA-2)  Human                           │
│        fix         review       escalation                       │
│             │           │                                        │
│             └─────┬─────┘                                        │
│                   ▼                                              │
│  ┌──────────────────────────────────────────┐                   │
│  │       KUBERNETES CLUSTER                  │                   │
│  │  PSS (AC-6) · NetworkPolicy (SC-7)       │                   │
│  │  RBAC (AC-2, AC-3) · Audit (AU-2)       │                   │
│  └──────────────────┬───────────────────────┘                   │
│                     │                                            │
│                     ▼                                            │
│  ┌──────────────────────────────────────────┐                   │
│  │       JSA-INFRASEC (CA-7)                │                   │
│  │  Falco · Kyverno · Gatekeeper · Drift    │                   │
│  │  "What's happening now?"                 │                   │
│  └──────────────────┬───────────────────────┘                   │
│                     │ evidence                                   │
│                     ▼                                            │
│  ┌──────────────────────────────────────────┐                   │
│  │       COMPLIANCE EVIDENCE                 │                   │
│  │  SSP · POA&M · SAR · Control Matrix      │                   │
│  │  "Here's the proof we're compliant"      │                   │
│  └──────────────────────────────────────────┘                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Control-to-Tool Mapping

### Access Control (AC)

| Control | Implementation | Tool | Manifest |
|---------|---------------|------|----------|
| AC-2 | Service account management | RBAC | `automation/kubernetes/rbac.yaml` |
| AC-3 | Namespace isolation + RBAC | K8s RBAC | `automation/kubernetes/rbac.yaml` |
| AC-6 | Pod security contexts, PSS | Kyverno | `automation/policies/kyverno/` |
| AC-17 | API server access audit | K8s audit | `automation/remediation/audit-logging.yaml` |

### Audit (AU)

| Control | Implementation | Tool | Manifest |
|---------|---------------|------|----------|
| AU-2 | Kubernetes audit policy + Falco | Falco | `automation/remediation/audit-logging.yaml` |
| AU-3 | Structured audit log format | K8s audit | `automation/remediation/audit-logging.yaml` |

### Assessment (CA)

| Control | Implementation | Tool | Manifest |
|---------|---------------|------|----------|
| CA-2 | Multi-scanner pipeline + JADE | scan-and-map.py | `automation/scanning/` |
| CA-7 | GHA + Falco + Kyverno | All agents | `.github/workflows/fedramp-compliance.yml` |

### Configuration Management (CM)

| Control | Implementation | Tool | Manifest |
|---------|---------------|------|----------|
| CM-2 | Git-tracked IaC baseline | Git | `automation/kubernetes/` |
| CM-6 | OPA/Kyverno admission control | Conftest/Kyverno | `automation/policies/` |
| CM-8 | Trivy SBOM + K8s API inventory | Trivy | `automation/scanning/trivy-config.yaml` |

### Identification (IA)

| Control | Implementation | Tool | Manifest |
|---------|---------------|------|----------|
| IA-5 | Secret detection + rotation | Gitleaks | `automation/scanning/gitleaks.toml` |

### Risk Assessment (RA)

| Control | Implementation | Tool | Manifest |
|---------|---------------|------|----------|
| RA-5 | Multi-scanner pipeline | Trivy/Semgrep/Gitleaks | `automation/scanning/` |

### System & Comms (SC)

| Control | Implementation | Tool | Manifest |
|---------|---------------|------|----------|
| SC-7 | Default deny NetworkPolicy | K8s NetworkPolicy | `automation/kubernetes/networkpolicy.yaml` |
| SC-28 | Encryption at rest (planned) | KMS/EBS | — |

### System Integrity (SI)

| Control | Implementation | Tool | Manifest |
|---------|---------------|------|----------|
| SI-2 | Container image scanning + auto-patch | Trivy | `automation/scanning/trivy-config.yaml` |

## How This Applied to NovaPay

NovaPay Federal came to us with zero NIST controls, no vulnerability management, and a VA hospital contract deadline. Here's what the architecture above delivered:

1. **35 findings identified** by JSA-DevSec across NovaPay's codebase — SQL injection, XSS, command injection, hardcoded credentials, container misconfigurations.

2. **27 auto-remediated** (E-D rank) — dependency upgrades, secret removal, config fixes. Zero human intervention.

3. **5 JADE-approved** (C rank) — Kyverno admission policies, NetworkPolicy, audit logging configuration.

4. **3 human-reviewed** (B rank) — credential management redesign, authentication flow hardening.

5. **15 NIST 800-53 controls** across 8 families documented with linked evidence, from gap assessment to audit-ready in 6 weeks.

## Design Principles

1. **Policy-first**: Every security control is a policy before it's code. OPA/Kyverno enforce at admission; Conftest validates in CI.

2. **Rank-based automation**: Not everything can or should be auto-fixed. The E-S rank system ensures appropriate human oversight (C-rank ceiling for AI, B-S for humans).

3. **Evidence-driven**: Every scan produces artifacts linked to NIST controls. The auditor doesn't need to trust us — they can verify every claim through the evidence chain.

4. **Defense in depth**: Controls exist at CI (pre-deploy), admission (deploy-time), and runtime (post-deploy). A finding caught at any layer is still caught.
