# Step 5: Automated Remediation

## How JSA Agents Fix Things

When a finding is ranked E or D, JSA-DevSec auto-remediates without human intervention. C-rank findings require JADE approval. This demonstrates **FedRAMP SI-2 (Flaw Remediation)**.

## Remediation Pipeline

```
Finding Detected → Rank Classified
  → E-D rank: JSA auto-fix → Verification scan → Close
  → C rank: JADE reviews → Approve/Deny → Fix → Verify → Close
  → B-S rank: Human notified → Manual review → Fix → Verify → Close
```

## DVWA Remediation Results

JSA-DevSec remediated **33 files** in under 60 seconds:

| Category | Files Fixed | Technique |
|----------|-----------|-----------|
| SQL Injection | 4 | Parameterized queries |
| Blind SQL Injection | 3 | Prepared statements |
| Command Injection | 4 | Input validation, allowlisting |
| File Inclusion | 1 | Path validation |
| Brute Force | 3 | Rate limiting, account lockout |
| File Upload | 1 | File type validation |
| CSRF | 2 | Token verification |
| XSS/JavaScript | 3 | Output encoding |
| API Security | 5 | Input sanitization |
| Misc PHP | 7 | Best practice fixes |

**Stats**: +1,511 lines added, -1,230 lines removed, net +281 lines

## Verification

After remediation, verification scans confirmed all findings resolved:

```bash
# Before: 2 Bandit findings, 33 vulnerable files
# After:  0 findings across all scanners
```

Evidence: `evidence/scan-reports/verification-scan.json`

## The Key Insight

Traditional compliance requires manual vulnerability remediation — weeks of developer time. The Iron Legion reduces this to seconds for E-D rank findings and hours for C-rank, with full audit trail for FedRAMP evidence.

## What Happens Next

With findings remediated, we generate compliance documentation. See [Step 6: Compliance Evidence](06-compliance-evidence.md).
