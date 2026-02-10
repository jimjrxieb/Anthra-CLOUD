# JSA-SecOps — Compliance Reporting for NovaSec Cloud

Compliance reporting and evidence collection for FedRAMP Moderate authorization.
This is the **third JSA agent type** in the Iron Legion — focused on continuous
compliance rather than scanning (devsec) or runtime enforcement (infrasec).

## Tools

| Script | What It Does |
|--------|-------------|
| `scan-and-map.py` | Run scanners → map findings to NIST 800-53 controls |
| `evidence-collector.sh` | Aggregate evidence artifacts for 3PAO review |

## Usage

```bash
# Run scan-and-map against DVWA target
python scan-and-map.py --client-name "NovaSec Cloud" --target-dir ../target-app/

# Collect evidence from scan reports and policy logs
./evidence-collector.sh --output-dir ../evidence/
```

## NIST Control Mapping

- **CA-2** (Security Assessments) — Automated assessment via scan-and-map
- **CA-7** (Continuous Monitoring) — Scheduled compliance reports
- **RA-5** (Vulnerability Scanning) — Scanner orchestration
- **AU-6** (Audit Review) — Evidence aggregation for auditors
