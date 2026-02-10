# NovaPay Federal — FedRAMP Authorization

A complete FedRAMP compliance engagement demonstrating how the **Iron Legion** security platform takes a fintech company from zero compliance to ATO-ready in weeks, not months.

## The Client

**NovaPay Federal** is a fintech company specializing in payroll and financial management for state and local governments. They recently landed a VA hospital payroll contract — but can't begin work without FedRAMP authorization.

| Field | Details |
|-------|---------|
| **Industry** | Fintech — payroll & financial management |
| **Clients** | State/local governments, federal agencies |
| **Stack** | EKS, React, Python API, PostgreSQL, S3, GitHub Actions |
| **Problem** | No compliance program — nothing mapped to NIST 800-53 |
| **Goal** | FedRAMP Low authorization |

## What We Did

```
┌─────────────────────────────────────────────────────────────────┐
│                NOVAPAY FEDERAL ENGAGEMENT                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   BEFORE                           AFTER                        │
│   ──────                           ─────                        │
│   0 NIST controls documented       15 controls across 8 families│
│   No vulnerability scanning        Automated CI/CD pipeline     │
│   No compliance evidence           Machine-verifiable artifacts │
│   12-18 months estimated           6 weeks actual               │
│                                                                  │
│   ENGAGEMENT PHASES                                              │
│   ─────────────────                                              │
│   Week 1-2: Gap Assessment (JSA-DevSec scans, JADE classifies)  │
│   Week 2-4: Control Implementation (policies, hardening, fixes)  │
│   Week 4-5: Documentation (SSP, POA&M, SAR, control matrix)     │
│   Week 5-6: Evidence + 3PAO Prep (continuous monitoring)         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Results

| Metric | Before | After |
|--------|--------|-------|
| NIST 800-53 controls documented | 0 | 15 |
| Open vulnerabilities | 35 | 0 |
| Automated evidence generation | None | Every code push |
| Continuous monitoring | None | CI/CD + Runtime |
| Policy enforcement | None | Kyverno + OPA + Conftest |

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

## Architecture

| Component | FedRAMP Role | Primary Controls |
|-----------|-------------|-----------------|
| **JSA-DevSec** | Pre-deployment scanning | RA-5, SI-2, CM-6, IA-5 |
| **JSA-InfraSec** | Runtime monitoring | CA-7, SC-7, AU-2, AC-2 |
| **JADE AI** | Risk classification + approval | CA-2, RA-2 |
| **Rank Classifier** | E-S risk categorization | RA-2 |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full Iron Legion → FedRAMP mapping.

## Quick Start

```bash
# Run NovaPay's application (DVWA stands in as a simplified version)
cd target-app && docker compose up -d

# Run security scan with NIST mapping
python automation/scanning/scan-and-map.py --target-dir target-app

# Validate Kubernetes policies
conftest test automation/kubernetes/ --policy automation/policies/conftest/

# View compliance documentation
ls compliance/
```

## Engagement Walkthrough

See [engagement/README.md](engagement/README.md) for the full 7-step guided tour of the NovaPay Federal engagement.

| Step | Guide | What It Shows |
|------|-------|---------------|
| 1 | [Client Assessment](engagement/01-client-assessment.md) | NovaPay's application and security posture |
| 2 | [Gap Analysis](engagement/02-gap-analysis.md) | Multi-scanner pipeline finds vulnerabilities |
| 3 | [Risk Classification](engagement/03-risk-classification.md) | Iron Legion rank system categorizes findings |
| 4 | [Control Mapping](engagement/04-control-mapping.md) | Findings mapped to NIST 800-53 controls |
| 5 | [Automated Remediation](engagement/05-automated-remediation.md) | JSA agents auto-fix E-D rank findings |
| 6 | [Evidence Generation](engagement/06-evidence-generation.md) | SSP, POA&M, SAR from real scan data |
| 7 | [Continuous Compliance](engagement/07-continuous-compliance.md) | GitHub Actions + runtime monitoring |

## Directory Structure

```
FedRAMP/
├── README.md                  # This file — NovaPay Federal story
├── ARCHITECTURE.md            # Iron Legion → FedRAMP mapping
├── ENGAGEMENT.md              # Client narrative and engagement details
├── target-app/                # NovaPay's application (DVWA)
├── evidence/                  # Scan results and remediation reports
├── compliance/                # FedRAMP compliance documentation
│   ├── ssp/                   # System Security Plan
│   ├── control-families/      # NIST 800-53 control details (8 families)
│   ├── poam/                  # Plan of Action & Milestones
│   ├── sar/                   # Security Assessment Report
│   └── control-matrix.md      # Controls × Tools × Evidence × Rank
├── automation/                # Security automation configs
│   ├── scanning/              # Trivy, Semgrep, Gitleaks configs
│   ├── policies/              # OPA, Kyverno, Gatekeeper policies
│   ├── remediation/           # Network, RBAC, audit templates
│   └── kubernetes/            # Hardened K8s manifests
├── engagement/                # 7-step engagement walkthrough
└── .github/workflows/         # CI/CD security pipelines
```

## The Iron Legion Rank System

| Rank | Automation | Handler | SLA |
|------|-----------|---------|-----|
| **E** | 95-100% | JSA auto-fix | Immediate |
| **D** | 70-90% | JSA auto-fix + log | < 24h |
| **C** | 40-70% | JADE approves | < 72h |
| **B** | 20-40% | Human + JADE | < 7 days |
| **S** | 0-5% | Human only | Risk-based |

## Powered by the Iron Legion

This engagement was delivered using the [GP-Copilot](https://github.com/jimjrxieb) security platform — AI-driven security agents built to CKS, CKA, and CCSP standards.

See the reusable FedRAMP toolkit: [GP-CONSULTING/07-FedRAMP-Ready](https://github.com/jimjrxieb)
