# Step 3: Finding Classification — Iron Legion Rank System

## The Rank System

Every finding gets classified on the **E-S scale**, which determines who handles it and how fast. This is our implementation of **FedRAMP RA-2 (Risk Categorization)**.

```
┌──────────────────────────────────────────────────────────────┐
│                  IRON LEGION RANK SYSTEM                      │
├──────┬──────────┬────────────────┬──────────────────────────┤
│ Rank │ Auto %   │ Who Handles    │ Examples                  │
├──────┼──────────┼────────────────┼──────────────────────────┤
│  E   │ 95-100%  │ JSA auto-fix   │ Missing timeout, assert  │
│  D   │ 70-90%   │ JSA auto-fix   │ SQLi fix, dep upgrade    │
│  C   │ 40-70%   │ JADE approves  │ Policy creation, arch    │
│  B   │ 20-40%   │ Human + JADE   │ Credential exposure      │
│  S   │ 0-5%     │ Human only     │ Strategy, compliance     │
└──────┴──────────┴────────────────┴──────────────────────────┘
```

## How Findings Get Ranked

The rank classifier uses a combination of:
1. **Scanner severity** (CVSS score, tool-native severity)
2. **Finding type** (known vulnerability patterns)
3. **Blast radius** (how many systems affected)
4. **Remediation complexity** (can it be auto-fixed?)

## DVWA Findings Classification

| Finding | Type | Severity | Rank | Handler |
|---------|------|----------|------|---------|
| Missing request timeout | Code quality | Medium | E | JSA auto-fix |
| Assert statement | Code quality | Low | E | JSA auto-fix |
| SQL injection (4 files) | Vulnerability | High | D | JSA auto-fix |
| XSS (3 files) | Vulnerability | High | D | JSA auto-fix |
| Command injection (4 files) | Vulnerability | Critical | C | JADE approves |
| CSRF missing (2 files) | Vulnerability | Medium | D | JSA auto-fix |

## FedRAMP Mapping

| Rank | NIST 800-53 Risk Level | Remediation SLA |
|------|----------------------|-----------------|
| E | Informational | Immediate |
| D | Low-Medium | < 24 hours |
| C | Medium-High | < 72 hours |
| B | High-Critical | < 7 days |
| S | Critical/Strategic | Risk-based |

## What Happens Next

Classified findings get mapped to specific NIST 800-53 controls. See [Step 4: NIST Control Mapping](04-nist-control-mapping.md).
