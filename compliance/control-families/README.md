# FedRAMP Control Families

Detailed control implementations for FedRAMP Low baseline. Each file covers one NIST 800-53 Rev 5 control family with specific controls mapped to Iron Legion automation.

## Families Documented

| File | Family | Controls Covered |
|------|--------|-----------------|
| `AC-access-control.md` | Access Control | AC-2, AC-3, AC-6, AC-17 |
| `AU-audit.md` | Audit & Accountability | AU-2, AU-3 |
| `CA-assessment.md` | Security Assessment | CA-2, CA-7 |
| `CM-config-mgmt.md` | Configuration Management | CM-2, CM-6, CM-8 |
| `IA-identification.md` | Identification & Auth | IA-5 |
| `RA-risk-assessment.md` | Risk Assessment | RA-5 |
| `SC-system-comms.md` | System & Comms Protection | SC-7, SC-28 |
| `SI-system-integrity.md` | System & Info Integrity | SI-2 |

## Iron Legion → NIST Mapping

| Agent | Primary Controls |
|-------|-----------------|
| JSA-DevSec | RA-5, SI-2, CM-6, IA-5 |
| JSA-InfraSec | CA-7, SC-7, AC-3, AU-2 |
| JADE (Supervisor) | CA-2, RA-2 (risk classification) |
| Rank Classifier | RA-2 (risk categorization) |
