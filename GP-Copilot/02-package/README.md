# 02-CLUSTER-HARDENING — Kubernetes Security Posture

Hardens cluster configuration, deploys admission control, enforces RBAC and PSS.

## Structure

```
golden-techdoc/   → CIS benchmark guides, Kyverno policy docs
playbooks/        → Step-by-step cluster audit → fix → verify workflows
outputs/          → Applied policies, audit results, OPA/Rego artifacts
summaries/        → Engagement summary with before/after metrics
```

## What This Package Does

- Cluster audit with Kubescape, Polaris, kube-bench, conftest
- PSS namespace labels (restricted/baseline/privileged)
- NetworkPolicy default-deny + service-aware allow rules
- Kyverno admission control (13 policies)
- LimitRange + ResourceQuota on all namespaces
- ArgoCD GitOps deployment with Kustomize overlays

## Anthra-FedRAMP Results

- Cluster audit: Mar 4, 2026
- Completion: Mar 16, 2026 — all namespaces labeled, netpols applied, Kyverno cleanup fixed
- Reports: `GP-S3/5-consulting-reports/01-instance/slot-3/02-package/`
