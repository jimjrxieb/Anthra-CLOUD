# Step 7: Continuous Monitoring

## FedRAMP CA-7: It Never Stops

FedRAMP authorization isn't a one-time event. The Authorization to Operate (ATO) requires continuous monitoring to maintain compliance. This is where the full Iron Legion works together.

## Monitoring Layers

```
┌─────────────────────────────────────────────────────┐
│               CONTINUOUS MONITORING                   │
├─────────────────────────────────────────────────────┤
│                                                       │
│  CI/CD (Every Push)        ← JSA-DevSec              │
│  ├── Trivy scan            (SI-2)                     │
│  ├── Semgrep scan          (RA-5)                     │
│  ├── Gitleaks              (IA-5)                     │
│  ├── Conftest              (CM-6)                     │
│  └── NIST mapping          (CA-2)                     │
│                                                       │
│  Admission (Every Deploy)  ← OPA/Kyverno             │
│  ├── Pod security          (AC-6)                     │
│  ├── Resource limits       (CM-6)                     │
│  ├── Image registries      (SI-2)                     │
│  └── NetworkPolicy         (SC-7)                     │
│                                                       │
│  Runtime (Continuous)      ← JSA-InfraSec             │
│  ├── Falco alerts          (AU-2)                     │
│  ├── Drift detection       (CM-2)                     │
│  ├── Policy enforcement    (CM-6)                     │
│  └── Network monitoring    (SC-7)                     │
│                                                       │
└─────────────────────────────────────────────────────┘
```

## GitHub Actions Workflows

| Workflow | Trigger | Controls |
|----------|---------|----------|
| `fedramp-compliance.yml` | Push + weekly | RA-5, SI-2, IA-5, CM-6, CA-2 |
| `policy-check.yml` | Push + PR | CM-6, AC-6 |
| `sast-analysis.yml` | Push + PR | RA-5 |
| `container-scan.yml` | Push + dispatch | SI-2 |

## What Continuous Monitoring Proves

To a FedRAMP auditor, this demonstrates:

1. **Automation**: Security checks run without human intervention
2. **Coverage**: Multiple tools cover different control families
3. **Traceability**: Every scan produces evidence linked to NIST controls
4. **Timeliness**: Issues detected within minutes of introduction
5. **Response**: E-D rank findings auto-remediated, B-S escalated

## The Portfolio Pitch

> "Using the Iron Legion agent fleet, we automated continuous compliance monitoring across 15 NIST 800-53 controls, with real-time vulnerability scanning, policy-as-code enforcement, and automated evidence generation — reducing compliance overhead from weeks to minutes per assessment cycle."
