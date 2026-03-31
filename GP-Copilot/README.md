# GP-Copilot — Anthra-CLOUD Engagement

GP-Copilot engagement artifacts for the Anthra Cloud platform. Everything an engineer needs to understand what was done, what was found, and what to do next.

## Directory Map

```
GP-Copilot/
  gp-outputs/       All scan results, reports, and summaries (centralized)
  gp-playbooks/     All engagement playbooks (centralized)
  01-package/        01-APP-SEC — code, deps, containers, CI
  02-package/        02-CLUSTER-HARDEN — policies, RBAC, admission, PSS
  03-package/        03-RUNTIME-SECURITY — Falco, watchers, responders
  04-package/        04-OPTIMIZE — cost optimization
  07-package/        07-CLOUD-SECURITY — AWS controls, Terraform, IAM
  jsa-variant-sums/  Session logs and cheatsheets
```

## Centralized Outputs (`gp-outputs/`)

All scan results, fix reports, and summaries in one place. Prefixed by package:

| Prefix | Package | What |
|--------|---------|------|
| `01-appsec-` | APP-SEC | Checkov, Trivy, Conftest scans, fix reports |
| `01-summary-` | APP-SEC | Engagement summary |
| `02-summary-` | CLUSTER-HARDEN | IaC scan report |
| `04-summary-` | OPTIMIZE | Cost baseline |
| `07-cloudsec-` | CLOUD-SECURITY | Terraform apply logs |

## Centralized Playbooks (`gp-playbooks/`)

Engagement playbooks tailored to Anthra. Follow in order within each package:

### 01 — App Security
| Playbook | Purpose |
|----------|---------|
| `01-appsec-01-baseline-scan.md` | Initial security scan |
| `01-appsec-02-remediation-plan.md` | Prioritize findings |
| `01-appsec-03-apply-fixes.md` | Apply D/E rank fixes |
| `01-appsec-04-post-fix-scan.md` | Verify fixes |
| `01-appsec-05-cicd-gate.md` | Wire into CI/CD |

### 02 — Cluster Hardening
| Playbook | Purpose |
|----------|---------|
| `02-cluster-01-cluster-audit.md` | Kubescape/CIS audit |
| `02-cluster-02-apply-hardening.md` | Apply hardening |
| `02-cluster-03-admission-control.md` | Kyverno/Gatekeeper |
| `02-cluster-04-golden-path.md` | Golden path templates |
| `02-cluster-05-gitops-promotion.md` | GitOps workflow |

### 03 — Runtime Security
| Playbook | Purpose |
|----------|---------|
| `03-runtime-01-deploy-falco.md` | Deploy Falco |
| `03-runtime-02-run-watchers.md` | Event watchers |
| `03-runtime-03-tune-falco.md` | Reduce noise |
| `03-runtime-04-test-responders.md` | Test auto-response |
| `03-runtime-05-operations.md` | Day-2 ops |

### 07 — Cloud Security
| Playbook | Purpose |
|----------|---------|
| `07-cloudsec-01-gap-analysis.md` | Identify gaps |
| `07-cloudsec-02-scan-and-map.md` | Scan and map controls |
| `07-cloudsec-03-remediate-controls.md` | Fix AWS findings |

## Package Directories

Each `0*-package/` directory contains the detailed artifacts for that engagement phase:

| Directory | Contents |
|-----------|----------|
| `outputs/` | Raw scan outputs (original location) |
| `playbooks/` | Engagement playbooks (original location) |
| `summaries/` | Executive summaries |
| `cost-savings/` | ROI calculations |
| `golden-techdoc/` | Technical documentation templates |

`gp-outputs/` and `gp-playbooks/` are the centralized copies — one place to find everything.

## Engagement Order

```
01-APP-SEC          Scan code, deps, containers, CI
  ↓
02-CLUSTER-HARDEN   Harden cluster, policies, RBAC, admission
  ↓
03-RUNTIME-SECURITY Deploy Falco, watchers, responders
  ↓
04-OPTIMIZE         Cost optimization, right-sizing
  ↓
07-CLOUD-SECURITY   AWS controls, Terraform hardening
```

## Infrastructure Playbooks

The deployment playbooks (how to deploy the actual infrastructure) are in a separate location:

```
infrastructure/playbook/    ← terraform, argocd, kubectl, VPC endpoints
```

See [infrastructure/playbook/README.md](../infrastructure/playbook/README.md).

---

## AWS Infrastructure Evidence — Staging (2026-03-30)

Deployed via Terraform (`infrastructure/terraform/`), managed by ArgoCD. All evidence collected via AWS CLI.

### 1. EKS Cluster Overview

```yaml
Name: anthra-staging-eks
Status: ACTIVE
Version: '1.32'
Platform: eks.39
Endpoint: https://<REDACTED>.gr7.us-east-1.eks.amazonaws.com
EncryptionConfig:
  - provider:
      keyArn: arn:aws:kms:us-east-1:<ACCOUNT>:key/<EKS-KMS-KEY-ID>
    resources:
      - secrets
```

EKS 1.32 with envelope encryption for Kubernetes secrets via KMS. 2 nodes (t3.medium), Multi-AZ across us-east-1a and us-east-1b.

### 2. IRSA — IAM Roles for Service Accounts (OIDC Provider)

```yaml
Url: oidc.eks.us-east-1.amazonaws.com/id/<OIDC-ID>
ClientIDList:
  - sts.amazonaws.com
Tags:
  - Key: Compliance
    Value: FedRAMP-Moderate
  - Key: ManagedBy
    Value: terraform
  - Key: Name
    Value: anthra-staging-eks-oidc
```

IRSA enables pod-level AWS identity — pods assume IAM roles via OIDC without long-lived credentials. Controls: AC-2 (Account Management), AC-6 (Least Privilege).

### 3. KMS Key — EKS Secrets Encryption at Rest

```yaml
Description: EKS secrets encryption for anthra-staging
KeyId: <EKS-KMS-KEY-ID>
State: Enabled
KeyRotationEnabled: true
```

Customer-managed KMS key with automatic annual rotation. Encrypts all Kubernetes secrets at rest in etcd. Control: SC-28 (Protection of Information at Rest).

### 4. GuardDuty — Threat Detection

```yaml
Status: ENABLED
Features:
  - CLOUD_TRAIL: ENABLED
  - DNS_LOGS: ENABLED
  - FLOW_LOGS: ENABLED
  - S3_DATA_EVENTS: ENABLED
  - EKS_AUDIT_LOGS: ENABLED
  - EBS_MALWARE_PROTECTION: ENABLED
  - RDS_LOGIN_EVENTS: ENABLED
Tags:
  Compliance: FedRAMP-Moderate
```

GuardDuty monitors CloudTrail, VPC Flow Logs, DNS, S3, EKS audit logs, EBS, and RDS login events. Control: SI-4 (System Monitoring).

### 5. CloudTrail — Audit Logging

```yaml
IsLogging: true
StartLoggingTime: '2026-03-31T01:44:44Z'
LatestDeliveryAttemptSucceeded: '2026-03-31T02:49:01Z'
S3Bucket: anthra-staging-cloudtrail-<ACCOUNT>
KmsKeyId: arn:aws:kms:us-east-1:<ACCOUNT>:key/<TRAIL-KMS-KEY-ID>
MultiRegion: true
```

Multi-region trail writing to encrypted S3 with CloudWatch Logs delivery. Controls: AU-2 (Event Logging), AU-3 (Content of Audit Records), AU-9 (Protection of Audit Information).

### 6. Secrets Manager — No Plaintext Credentials

```yaml
Secrets:
  - Name: anthra/staging/db-credentials
    KmsKeyId: arn:aws:kms:us-east-1:<ACCOUNT>:key/<SECRETS-KMS-KEY-ID>
    RotationEnabled: true

  - Name: anthra/staging/api-keys
    KmsKeyId: arn:aws:kms:us-east-1:<ACCOUNT>:key/<SECRETS-KMS-KEY-ID>
    RotationEnabled: pending
```

All credentials stored in Secrets Manager, encrypted with customer-managed KMS keys. DB credentials have automatic 90-day rotation via Lambda. Controls: IA-5 (Authenticator Management), SC-28 (Protection at Rest).

### 7. Kubernetes — Workload Status

```
NODES (2 — Multi-AZ):
  ip-10-0-10-x.ec2.internal   Ready   v1.32.9-eks   us-east-1a
  ip-10-0-11-x.ec2.internal   Ready   v1.32.9-eks   us-east-1b

PODS (8/8 Running — anthra namespace):
  anthra-api          2/2 Running   0 restarts
  anthra-db           2/2 Running   0 restarts
  anthra-log-ingest   2/2 Running   0 restarts
  anthra-ui           2/2 Running   0 restarts

KYVERNO POLICIES (7 — Audit mode):
  anthra-disallow-latest-tag              Ready
  anthra-disallow-privilege-escalation    Ready
  anthra-require-drop-all-capabilities    Ready
  anthra-require-readonly-rootfs          Ready
  anthra-require-resource-limits          Ready
  anthra-require-run-as-nonroot           Ready
  anthra-require-seccomp-profile          Ready
```

All workloads deployed via ArgoCD from GitOps overlays (Kustomize). 7 Kyverno admission policies active in audit mode, mapped to NIST AC-6, CM-6, SC-5, SC-7, SI-7.

### 8. Falco — Runtime Threat Detection

```yaml
Deployment: DaemonSet (1 pod per node)
Driver: modern_ebpf (eBPF syscall monitoring)
Namespace: falco
Pods: 2/2 Running
Output: JSON to stdout + webhook-ready
Rules: 65 rules across 8 files (MITRE ATT&CK mapped)
Coverage: crypto-mining, data-exfiltration, privilege-escalation,
          persistence, k8s-audit, service-mesh
```

Falco monitors every syscall on every node via eBPF. No kernel module needed on EKS managed nodes. Controls: SI-4 (System Monitoring), AU-2 (Event Logging), IR-4 (Incident Handling).

### 9. Karpenter — Node Auto-Provisioning

```yaml
Version: v1.4.0
NodePool: default
  Instance Families: m5, m6i, m7i, c5, c6i, c7i, r5, r6i
  Sizes: medium, large, xlarge, 2xlarge
  Capacity: spot preferred, on-demand fallback
  Consolidation: WhenEmptyOrUnderutilized (30s)
  Disruption Budget: 10% (5% during business hours)
  Node Expiry: 168h (7 days)
EC2NodeClass: default
  AMI: AL2023@latest (EKS-optimized)
  EBS: 50Gi gp3, encrypted, 3000 IOPS
  IMDSv2: required (blocks SSRF credential theft)
Status: Ready — waiting for scale-up demand
```

Karpenter replaces Cluster Autoscaler with right-sized, bin-packed nodes. Spot-first strategy saves 60-80% on interruptible workloads. Controls: CM-6 (Configuration Settings), SC-5 (DoS Protection via resource limits).

### 10. Container Insights — Observability

```yaml
Namespace: amazon-cloudwatch
FluentBit DaemonSet: 2/2 Running (1 per node)
Log Destination: CloudWatch Logs (/aws/containerinsights/anthra-staging-eks/)
Metrics: Container CPU, memory, network, filesystem
Collection Interval: 60s
```

FluentBit streams container logs and metrics to CloudWatch. Enables per-pod cost attribution when combined with Karpenter cost-tracking labels. Controls: AU-2 (Event Logging), SI-4 (System Monitoring).

### NIST 800-53 Control Mapping

| Control | Description | Evidence |
|---------|-------------|----------|
| AC-2 | Account Management | IRSA OIDC, K8s RBAC ServiceAccounts |
| AC-6 | Least Privilege | Kyverno (non-root, drop caps, no privilege escalation) |
| AU-2 | Event Logging | CloudTrail, Falco, FluentBit Container Insights |
| AU-3 | Audit Record Content | CloudTrail event structure, Falco JSON output |
| AU-9 | Protection of Audit Info | S3 versioning + KMS on trail bucket |
| CM-6 | Configuration Settings | Kyverno (resource limits, seccomp, readonly rootfs) |
| IA-5 | Authenticator Management | Secrets Manager (KMS, rotation enabled) |
| IR-4 | Incident Handling | Falco runtime detection (65 rules, MITRE ATT&CK) |
| SC-5 | Denial of Service Protection | Kyverno resource limits, LimitRanges, Karpenter |
| SC-7 | Boundary Protection | NetworkPolicies (default-deny), seccomp profiles |
| SC-28 | Protection at Rest | KMS on EKS secrets, RDS, S3, Secrets Manager |
| SI-4 | System Monitoring | GuardDuty (7 sources), Falco (eBPF), Container Insights |
| SI-7 | Software Integrity | Kyverno (read-only rootfs, drop all capabilities) |
