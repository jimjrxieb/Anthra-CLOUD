# JADE + JSA Agent Cheatsheet — Anthra-FedRAMP

## Agent Mapping

| Agent | Package | Domain |
|-------|---------|--------|
| jsa-devsec | 01-APP-SEC | Code, deps, Dockerfiles, CI |
| jsa-infrasec | 02-CLUSTER-HARDENING | Policies, RBAC, admission, PSS |
| jsa-monitor | 03-DEPLOY-RUNTIME | Falco, events, drift, forensics |

## Rank Routing

| Rank | Automation | Who Decides |
|------|-----------|-------------|
| E (95-100%) | Auto-fix | Pattern NPCs |
| D (70-90%) | Auto-fix + log | Pattern NPCs |
| C (40-70%) | JADE proposes | Katie → JADE approval |
| B (20-40%) | Human decides | JADE provides intel |
| S (0-5%) | Human only | JADE provides dashboards |

## Anthra-Specific Notes

- Client: NovaSec Cloud (FedRAMP Moderate)
- 8 priority NIST controls: AC-2, AC-6, AU-2, CM-6, SC-7, SC-8, SI-2, SI-4
- ArgoCD manages deployment via Kustomize overlays (dev/staging/prod)
- Cluster: Kind lab (gp-lab), EKS planned for prod
