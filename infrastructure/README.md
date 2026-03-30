# Infrastructure

Everything needed to deploy the Anthra Cloud platform across environments.

## Directory Map

```
infrastructure/
  cloudformation/     Dev environment — AWS stacks (VPC, Security, EKS, RDS, Monitoring)
  terraform/          Staging/Production — modular IaC with separate state per environment
  gitops/             Kustomize + ArgoCD — what runs ON the cluster (primary deploy path)
    anthra-api/       base/ + overlays/{dev,staging,prod}/ + argocd/
    anthra-db/        base/ + overlays/{dev,staging,prod}/ + argocd/
    anthra-log-ingest/ base/ + overlays/{dev,staging,prod}/ + argocd/
    anthra-ui/        base/ + overlays/{dev,staging,prod}/ + argocd/
  k8s/                Raw manifests — kubectl apply -f fallback (no GitOps dependency)
  playbook/           Step-by-step deployment guides — how any engineer deploys this app
```

## Environment Strategy

| Environment | Tool | State | Purpose |
|-------------|------|-------|---------|
| Dev | CloudFormation | AWS stacks | Quick iteration, throwaway |
| Staging | Terraform | `s3://anthra-fedramp-tfstate/staging/` | Where we live. Every change lands here first |
| Production | Terraform | `s3://anthra-fedramp-tfstate/production/` | Promotion only. Last step. See playbook 09 |

## Deployment Paths

**AWS infrastructure** (VPC, EKS, RDS, monitoring, security):

```
Dev:        cloudformation/deploy.sh  (01-vpc → 02-security → 03-eks → 04-rds → 05-monitoring)
Staging:    terraform apply -var-file="environments/staging/terraform.tfvars"
Production: terraform apply -var-file="environments/production/terraform.tfvars"
```

**Application workloads** (API, DB, UI, log-ingest):

```
GitOps:     gitops/anthra-*/argocd/ + overlays/   (Kustomize + ArgoCD — primary path)
Fallback:   kubectl apply -f k8s/                  (raw manifests — emergency only)
```

## gitops/ — Kustomize + ArgoCD

Each app follows the same structure:

```
gitops/anthra-<service>/
  base/       Shared manifests (Deployment, Service, ConfigMap)
  overlays/   Environment-specific patches (dev, staging, prod)
  argocd/     ArgoCD Application definitions
```

ArgoCD watches these directories. Push to git, ArgoCD syncs. See [playbook 04](playbook/04-kustomize-argocd-deploy.md).

## k8s/ — Fallback Manifests

Raw Kubernetes manifests for direct `kubectl apply -f` when ArgoCD is unavailable. Contains namespace, deployments, services, ingress, RBAC, network policies, PVCs, resource quotas, and secrets.

This is the escape hatch, not the primary path. See [playbook 05](playbook/05-k8s-fallback-deploy.md).

## Playbooks

Runbooks that minimize drift. Any engineer follows the same steps. See [playbook/README.md](playbook/README.md) for the full order of operations.

## Rules

- CloudFormation for dev. Terraform for staging and production. Never mix.
- Staging first, production last. Always.
- ArgoCD-managed resources are fixed in git, never kubectl. See `.claude/rules/argocd-rules.md`.
- `k8s/` manifests are fallback only. If ArgoCD is running, use it.
