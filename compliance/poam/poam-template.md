# Plan of Action & Milestones (POA&M) Template

## POA&M Instructions

This template tracks security findings that require remediation. Each entry maps to a NIST 800-53 control and tracks progress from discovery through closure.

## Entry Template

| Field | Value |
|-------|-------|
| **POA&M ID** | POAM-XXXX |
| **Finding** | [Description of the finding] |
| **Control** | [NIST 800-53 control ID] |
| **Source** | [Scanner/tool that found it] |
| **Severity** | [Critical/High/Medium/Low] |
| **Iron Legion Rank** | [E/D/C/B/S] |
| **Status** | [Open/In Progress/Closed] |
| **Detected Date** | [YYYY-MM-DD] |
| **Scheduled Completion** | [YYYY-MM-DD] |
| **Actual Completion** | [YYYY-MM-DD or —] |
| **Responsible Party** | [JSA-DevSec/JSA-InfraSec/JADE/Human] |
| **Remediation** | [Description of fix] |
| **Verification** | [How it was verified] |
| **Evidence** | [Path to evidence file] |

## Status Definitions

| Status | Definition |
|--------|-----------|
| Open | Finding identified, not yet addressed |
| In Progress | Remediation underway |
| Closed | Remediated and verified |
| Risk Accepted | Accepted with documented justification |
| False Positive | Verified as not applicable |

## Rank-Based SLAs

| Rank | Max Remediation Time | Approver |
|------|---------------------|----------|
| E | Immediate (auto-fix) | JSA auto |
| D | 24 hours | JSA auto |
| C | 72 hours | JADE |
| B | 7 days | Human |
| S | Risk-based | Human (executive) |
