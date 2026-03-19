# 01-APP-SEC — Pre-Deploy Application Security

Scans code, dependencies, Dockerfiles, and CI pipelines before anything ships.

## Structure

```
golden-techdoc/   → Engagement guides, scanner capabilities, decision trees
playbooks/        → Step-by-step runbooks for scan → triage → fix workflows
outputs/          → Scan results, remediation artifacts, triage reports
summaries/        → Package overview and engagement summaries
```

## What This Package Does

- Runs 8 parallel security scanners (Semgrep, Bandit, Trivy, gitleaks, Checkov, hadolint, grype, conftest)
- Auto-triages findings by severity with fixer scripts for Dockerfiles, Python, and web vulnerabilities
- Integrates into GitHub Actions CI as a blocking gate

## Anthra-FedRAMP Results

- Baseline: Feb 12, 2026 — 41 findings across API, UI, log-ingest, DB
- Remediations: Security contexts, secrets management, MD5→bcrypt migration
- Reports: `GP-S3/5-consulting-reports/01-instance/slot-3/01-package/`
