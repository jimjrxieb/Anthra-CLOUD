# Step 4: NIST 800-53 Control Mapping

## From Findings to Controls

The `scan-and-map.py` tool automatically maps each finding to the NIST 800-53 Rev 5 control it relates to. This is the core of **FedRAMP CA-2 (Security Assessments)**.

## The Mapping Logic

```python
# From automation/scanning/scan-and-map.py
FINDING_TO_NIST = {
    "sql_injection":        {"controls": ["RA-5", "SI-2"], "rank": "D"},
    "command_injection":    {"controls": ["RA-5", "SI-2"], "rank": "C"},
    "hardcoded_secret":     {"controls": ["IA-5"],         "rank": "B"},
    "cve_critical":         {"controls": ["SI-2", "RA-5"], "rank": "C"},
    "misconfiguration":     {"controls": ["CM-6"],         "rank": "D"},
    "missing_netpol":       {"controls": ["SC-7"],         "rank": "D"},
    ...
}
```

## Agent-to-Control Mapping

This is what makes the demo powerful — each Iron Legion agent maps directly to NIST control families:

| Agent | Role | Primary Controls |
|-------|------|-----------------|
| **JSA-DevSec** | Pre-deployment scanning | RA-5, SI-2, CM-6, IA-5, AC-6 |
| **JSA-InfraSec** | Runtime monitoring | CA-7, SC-7, AU-2, AU-3, AC-2 |
| **JADE** | Supervisor / assessor | CA-2, RA-2 |
| **Rank Classifier** | Risk categorization | RA-2 |

## DVWA Findings → NIST Controls

| Finding | Control | Family | Evidence |
|---------|---------|--------|----------|
| SQL injection | RA-5, SI-2 | Risk Assessment, System Integrity | `evidence/scan-reports/` |
| Missing timeout | SI-2 | System Integrity | `evidence/scan-reports/initial-scan.json` |
| XSS vulnerabilities | RA-5 | Risk Assessment | `evidence/remediation/SECURITY_REMEDIATION.md` |
| Command injection | RA-5, SI-2 | Risk Assessment, System Integrity | `evidence/remediation/SECURITY_REMEDIATION.md` |

## Running the Mapping

```bash
python automation/scanning/scan-and-map.py --target-dir target-app
# Output: evidence/scan-reports/nist-mapping-report.json
```

## What Happens Next

Findings that are E-D rank get auto-remediated. See [Step 5: Automated Remediation](05-automated-remediation.md).
