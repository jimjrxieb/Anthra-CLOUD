# Step 6: Compliance Evidence Generation

## From Scans to FedRAMP Documentation

The scan results, remediation actions, and policy validations generate the artifacts a 3PAO auditor needs. This demonstrates **FedRAMP CA-2 (Security Assessments)**.

## Generated Artifacts

### System Security Plan (SSP)
Location: `compliance/ssp/`

The SSP documents how each NIST 800-53 control is implemented:

| Document | Purpose |
|----------|---------|
| `ssp-skeleton.md` | Full SSP with control status table |
| `system-description.md` | System overview, components, data flows |
| `authorization-boundary.md` | What's in/out of scope |

### Control Family Details
Location: `compliance/control-families/`

Eight control families with 15 fully documented controls:

| Family | Controls | Key Evidence |
|--------|----------|-------------|
| AC (Access Control) | AC-2, AC-3, AC-6, AC-17 | RBAC manifests, PSS policies |
| AU (Audit) | AU-2, AU-3 | Audit policy, Falco rules |
| CA (Assessment) | CA-2, CA-7 | Scan pipeline, monitoring config |
| CM (Config Management) | CM-2, CM-6, CM-8 | Git baseline, OPA/Kyverno policies |
| IA (Identification) | IA-5 | Gitleaks config, secret detection |
| RA (Risk Assessment) | RA-5 | Multi-scanner results |
| SC (System & Comms) | SC-7, SC-28 | NetworkPolicy manifests |
| SI (System Integrity) | SI-2 | Trivy config, remediation report |

### Plan of Action & Milestones (POA&M)
Location: `compliance/poam/`

Tracks every finding from discovery to closure:
- 3 findings identified
- 3 findings closed (100% remediation)
- Full audit trail with evidence links

### Security Assessment Report (SAR)
Location: `compliance/sar/`

Executive summary of the assessment, findings, and remediation status.

### Control Matrix
Location: `compliance/control-matrix.md`

Cross-reference: Control x Tool x Evidence x Rank — the single-page view an auditor loves.

## The Key Insight

In a traditional FedRAMP engagement, this documentation takes weeks to compile manually. Our toolchain generates it automatically from real scan data, with traceable links between findings, controls, and evidence.

## What Happens Next

Compliance isn't a one-time event — it requires continuous monitoring. See [Step 7: Continuous Monitoring](07-continuous-monitoring.md).
