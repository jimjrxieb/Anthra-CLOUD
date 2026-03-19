# 03-DEPLOY-RUNTIME — Runtime Security Monitoring

Deploys Falco for runtime threat detection, watchers for drift/events/secrets, responders for auto-remediation.

## Structure

```
golden-techdoc/   → Falco rule docs, watcher capabilities
playbooks/        → Deploy → verify → tune → monitor workflows
outputs/          → Watcher reports, Falco tuning results
summaries/        → Engagement summary with alert metrics
```

## What This Package Does

- Falco DaemonSet on every node (syscall + K8s audit monitoring)
- 10 watchers: apparmor, audit, drift, events, network, pss, seccomp, secrets, supply-chain
- Falco rule tuning (week 2 — reduce false positives)
- Optional: jsa-infrasec autonomous agent for E/D rank auto-remediation

## Anthra-FedRAMP Results

- Falco deployed: running on both nodes
- Watcher reports: Mar 12, 2026 — 10 reports generated
- Next: Falco tuning, responder testing
- Reports: `GP-S3/5-consulting-reports/01-instance/slot-3/03-package/`
