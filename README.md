# FedRAMP Compliance Demo

Automated FedRAMP compliance using the **Iron Legion** security platform against a real vulnerable web application.

## What This Demonstrates

A complete FedRAMP compliance lifecycle — from vulnerability scanning to NIST 800-53 control mapping to automated remediation with evidence generation — powered by AI-driven security agents.

```
Developer Push → Security Scans → Rank Classification (E-S)
  → Auto-Remediation (E-D) or Human Escalation (B-S)
  → NIST 800-53 Control Mapping → Evidence Generation
  → SSP / POA&M / SAR → Continuous Monitoring
```

## Architecture

| Component | Purpose | FedRAMP Controls |
|-----------|---------|-----------------|
| **JSA-DevSec** | Pre-deployment scanning | RA-5, SI-2, CM-6, IA-5 |
| **JSA-InfraSec** | Runtime monitoring | CA-7, SC-7, AU-2, AC-2 |
| **JADE AI** | Risk classification + approval | CA-2, RA-2 |
| **Rank Classifier** | E-S risk categorization | RA-2 |

## FedRAMP Controls Covered

| Control | Name | Status |
|---------|------|--------|
| AC-2, AC-3, AC-6, AC-17 | Access Control | Implemented |
| AU-2, AU-3 | Audit & Accountability | Implemented |
| CA-2, CA-7 | Security Assessment | Implemented |
| CM-2, CM-6, CM-8 | Configuration Management | Implemented |
| IA-5 | Identification & Auth | Implemented |
| RA-5 | Risk Assessment | Implemented |
| SC-7, SC-28 | System & Comms Protection | Implemented / Planned |
| SI-2 | System & Info Integrity | Implemented |

**15 controls** fully documented across **8 families** against **FedRAMP Low** baseline.

## Quick Start

```bash
# Run the target application
cd target-app && docker compose up -d

# Run security scan with NIST mapping
python automation/scanning/scan-and-map.py --target-dir target-app

# Validate Kubernetes policies
conftest test automation/kubernetes/ --policy automation/policies/conftest/

# View compliance documentation
ls compliance/
```

## Directory Structure

```
FedRAMP/
├── README.md                  # This file
├── ARCHITECTURE.md            # Iron Legion → FedRAMP mapping
├── LICENSE                    # GPL-3.0 (DVWA)
├── compose.yml                # Root-level Docker Compose
├── target-app/                # DVWA (intentionally vulnerable target)
│   ├── compose.yml            # Standalone DVWA
│   ├── Dockerfile
│   └── ...                    # PHP app, config, tests
├── evidence/                  # Scan results and remediation reports
│   ├── scan-reports/          # Trivy, Semgrep, Bandit results
│   └── remediation/           # Remediation documentation
├── compliance/                # FedRAMP compliance documentation
│   ├── ssp/                   # System Security Plan
│   ├── control-families/      # NIST 800-53 control details
│   ├── poam/                  # Plan of Action & Milestones
│   ├── sar/                   # Security Assessment Report
│   └── control-matrix.md      # Controls × Tools × Evidence × Rank
├── automation/                # Security automation configs
│   ├── scanning/              # Trivy, Semgrep, Gitleaks configs
│   ├── policies/              # OPA, Kyverno, Gatekeeper policies
│   ├── remediation/           # Network, RBAC, audit templates
│   └── kubernetes/            # Hardened K8s manifests
├── demo/                      # Step-by-step walkthrough
│   ├── 01-07 guides           # 7-step demo flow
│   └── diagrams/              # Mermaid architecture diagrams
└── .github/workflows/         # CI/CD security pipelines
    ├── fedramp-compliance.yml # Primary: scan + map + evidence
    ├── sast-analysis.yml      # CodeQL + Semgrep
    ├── container-scan.yml     # Build + Trivy
    ├── policy-check.yml       # Conftest + Kyverno
    └── pytest.yml             # Unit tests
```

## The Iron Legion Rank System

| Rank | Automation | Handler | SLA |
|------|-----------|---------|-----|
| **E** | 95-100% | JSA auto-fix | Immediate |
| **D** | 70-90% | JSA auto-fix + log | < 24h |
| **C** | 40-70% | JADE approves | < 72h |
| **B** | 20-40% | Human + JADE | < 7 days |
| **S** | 0-5% | Human only | Risk-based |

## Demo Walkthrough

See [demo/README.md](demo/README.md) for the full 7-step guided tour.

## Part of GP-Copilot

This repo is a standalone FedRAMP compliance demonstration from the [GP-Copilot](https://github.com/jimjrxieb) security platform.
