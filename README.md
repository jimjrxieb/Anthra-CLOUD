# NovaSec Cloud — FedRAMP Moderate Compliance Demo

**Client:** NovaSec Cloud (fictional SaaS security monitoring platform)
**Objective:** FedRAMP Moderate authorization to sell to DHS
**Baseline:** NIST 800-53 Rev 5, FedRAMP Moderate (323 controls)
**Engagement by:** GuidePoint Security Engineering — Iron Legion Platform

---

## The Scenario

NovaSec Cloud is a multi-tenant SaaS security monitoring platform — think smaller
Splunk focused on federal agencies. They need FedRAMP Moderate authorization to
win a DHS contract for centralized log aggregation and threat detection.

**Stack:** EKS (multi-tenant), React dashboard, Python/Go APIs, Elasticsearch,
PostgreSQL, S3 (evidence storage), Kafka (event streaming)

**Challenge:** Multi-tenant isolation, transmission confidentiality, real-time
monitoring, and continuous compliance — all auditable by a 3PAO.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     NovaSec Cloud + Iron Legion                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
│  │ Tenant A     │  │ Tenant B     │  │ Tenant C     │  ← Isolated NS  │
│  │ (DHS SOC)    │  │ (DoD SIEM)   │  │ (FBI Logs)   │                  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                  │
│         │                 │                 │                           │
│         └────────────┬────┴────┬────────────┘                          │
│                      │         │                                        │
│              ┌───────▼───┐ ┌───▼───────┐                               │
│              │  Kafka    │ │ Postgres  │  ← Shared infra (encrypted)   │
│              │  (events) │ │ (metadata)│                                │
│              └───────┬───┘ └───┬───────┘                               │
│                      │         │                                        │
│              ┌───────▼─────────▼───────┐                               │
│              │    Elasticsearch        │  ← Log storage (per-tenant)   │
│              │    (search + analytics) │                                │
│              └─────────────────────────┘                               │
│                                                                         │
│  ═══════════════════ IRON LEGION OVERLAY ═══════════════════           │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
│  │ JSA-DevSec   │  │ JSA-InfraSec │  │ JSA-SecOps   │                  │
│  │ Pre-deploy   │  │ Runtime      │  │ Compliance   │                  │
│  │ scanning     │  │ enforcement  │  │ reporting    │                  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                  │
│         └────────────┬────┴────┬────────────┘                          │
│                      │    JADE │                                        │
│              ┌───────▼─────────▼───────┐                               │
│              │  JADE Supervisor (C-rank)│                               │
│              │  Approve/escalate/report │                               │
│              └─────────────────────────┘                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 8 Priority Controls

| # | Control | Name | Policy Files | JSA Agent |
|---|---------|------|-------------|-----------|
| 1 | **AC-2** | Account Management | [OPA](policies/opa/ac2_account_management.rego), [Kyverno](policies/kyverno/enforce-tenant-isolation.yaml), [GK](policies/gatekeeper/constraints/tenant-isolation-constraint.yaml) | SecOps |
| 2 | **AC-6** | Least Privilege | [OPA](policies/opa/ac6_least_privilege.rego), [Kyverno](policies/kyverno/require-least-privilege.yaml), [GK](policies/gatekeeper/constraints/least-privilege-constraint.yaml) | DevSec |
| 3 | **AU-2** | Audit Events | [OPA](policies/opa/au2_audit_events.rego), [Kyverno](policies/kyverno/require-audit-logging.yaml) | InfraSec |
| 4 | **CM-6** | Configuration Settings | [OPA](policies/opa/cm6_configuration_settings.rego), [Kyverno](policies/kyverno/require-resource-limits.yaml) | DevSec |
| 5 | **SC-7** | Boundary Protection | [OPA](policies/opa/sc7_boundary_protection.rego), [Kyverno](policies/kyverno/enforce-network-boundaries.yaml), [GK](policies/gatekeeper/constraints/network-boundaries-constraint.yaml) | InfraSec |
| 6 | **SC-8** | Transmission Confidentiality | [OPA](policies/opa/sc8_transmission_confidentiality.rego), [Kyverno](policies/kyverno/require-tls-everywhere.yaml), [GK](policies/gatekeeper/constraints/require-tls-constraint.yaml) | InfraSec |
| 7 | **SI-2** | Flaw Remediation | [OPA](policies/opa/si2_flaw_remediation.rego) | DevSec |
| 8 | **SI-4** | System Monitoring | [OPA](policies/opa/si4_system_monitoring.rego), [Falco](jsa-infrasec/falco-rules.yaml) | InfraSec |

---

## Quick Start

```bash
# 1. DVWA target app (the deliberately vulnerable app JSA agents scan)
cd target-app && docker compose up -d

# 2. Run OPA policy validation
conftest test policies/opa/ --policy policies/opa/

# 3. Run full scan-and-map against DVWA
python jsa-secops/scan-and-map.py \
  --client-name "NovaSec Cloud" \
  --target-dir target-app/ \
  --dry-run

# 4. Collect evidence for 3PAO review
./jsa-secops/evidence-collector.sh
```

---

## Directory Structure

```
FedRAMP/
├── README.md                    ← You are here
├── target-app/                  ← DVWA (deliberately vulnerable target)
├── policies/
│   ├── opa/                     ← 8 Rego policies (CI via Conftest)
│   ├── kyverno/                 ← 7 admission policies
│   └── gatekeeper/              ← 4 template/constraint pairs
├── jsa-devsec/                  ← Pre-deploy scanning configs
├── jsa-infrasec/                ← Runtime enforcement (Falco rules)
├── jsa-secops/                  ← Compliance reporting (NEW)
├── oscal/                       ← Machine-readable compliance (OSCAL)
├── docs/                        ← Engagement documentation
└── .github/workflows/           ← CI/CD: scan + compliance report
```

---

## Iron Legion Agents in This Engagement

| Agent | Phase | Tools | Rank Range |
|-------|-------|-------|------------|
| **JSA-DevSec** | Pre-deploy | Trivy, Semgrep, Gitleaks, Conftest | E-D |
| **JSA-InfraSec** | Runtime | Falco, NetworkPolicy, Pod isolation | D-C |
| **JSA-SecOps** | Reporting | scan-and-map, evidence-collector | D-C |
| **JADE** | Supervisor | Approval, escalation, rank gating | C (max) |

---

## FedRAMP Moderate vs Low

| Aspect | Low (NovaPay - previous) | Moderate (NovaSec Cloud) |
|--------|--------------------------|--------------------------|
| Controls | 125 | **323** |
| Multi-tenant | No | **Yes** |
| Transmission encryption | Basic TLS | **mTLS + SC-8** |
| Runtime monitoring | Optional | **Required (SI-4)** |
| OSCAL | No | **Yes** |
| Audit depth | Basic | **Full AU-2/AU-3** |
