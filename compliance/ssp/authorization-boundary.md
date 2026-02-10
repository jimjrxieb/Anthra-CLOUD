# Authorization Boundary

## Boundary Definition

The authorization boundary encompasses:

1. **Target Application** — DVWA running in a hardened Kubernetes namespace
2. **Security Automation** — GP-Copilot agents (JSA-DevSec, JSA-InfraSec, JADE)
3. **Policy Engine** — OPA/Gatekeeper, Kyverno admission controllers
4. **CI/CD Pipeline** — GitHub Actions workflows with security gates
5. **Evidence Store** — Scan reports, compliance mappings, POA&M artifacts

## Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                   AUTHORIZATION BOUNDARY                         │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │  CI/CD        │    │  Kubernetes   │    │  Evidence     │      │
│  │  Pipeline     │    │  Cluster      │    │  Store        │      │
│  │              │    │              │    │              │       │
│  │  GitHub      │───▶│  Target App  │    │  Scan Reports│       │
│  │  Actions     │    │  (DVWA)      │    │  NIST Maps   │       │
│  │              │    │              │    │  POA&M       │       │
│  │  JSA-DevSec  │    │  JSA-InfraSec│    │  SSP Docs    │       │
│  │  Scanners    │    │  Watchers    │    │              │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         │                   │                   ▲                │
│         │                   │                   │                │
│         ▼                   ▼                   │                │
│  ┌──────────────────────────────────────────────┐               │
│  │            JADE AI Supervisor                 │               │
│  │     Rank Classification + NIST Mapping        │               │
│  │     C-rank ceiling (never elevated)           │               │
│  └──────────────────────────────────────────────┘               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ (B-S rank escalation)
                    ┌──────────────────┐
                    │  Human Operator   │
                    │  (Out of Boundary)│
                    └──────────────────┘
```

## External Connections

| Connection | Direction | Purpose | Control |
|-----------|-----------|---------|---------|
| GitHub API | Outbound | Code push, PR creation | SC-7 |
| Container Registry | Outbound | Image pull (ghcr.io) | SI-2 |
| Vulnerability DBs | Outbound | CVE data (NVD, GHSA) | RA-5 |
| Human Escalation | Outbound | B-S rank finding alerts | CA-2 |

## What Is Excluded

- End-user browsers (outside boundary)
- Human operator workstations (outside boundary)
- Upstream DVWA repository (external)
- Third-party vulnerability databases (external data source)
