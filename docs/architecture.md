# NovaSec Cloud — Architecture

## NovaSec Cloud Platform Architecture

```
                    ┌─────────────────────────┐
                    │     CloudFront CDN       │
                    │     (TLS termination)    │
                    └──────────┬──────────────┘
                               │ HTTPS only
                    ┌──────────▼──────────────┐
                    │     ALB Ingress          │
                    │     (TLS + WAF)          │
                    └──────────┬──────────────┘
                               │
                    ┌──────────▼──────────────┐
                    │     Istio Ingress GW     │
                    │     (mTLS enforcement)   │
                    └──────────┬──────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
    ┌─────▼─────┐       ┌─────▼─────┐       ┌─────▼─────┐
    │ Tenant A  │       │ Tenant B  │       │ Tenant C  │
    │ Namespace │       │ Namespace │       │ Namespace │
    │           │       │           │       │           │
    │ ┌───────┐ │       │ ┌───────┐ │       │ ┌───────┐ │
    │ │React  │ │       │ │React  │ │       │ │React  │ │
    │ │UI     │ │       │ │UI     │ │       │ │UI     │ │
    │ └───┬───┘ │       │ └───┬───┘ │       │ └───┬───┘ │
    │     │     │       │     │     │       │     │     │
    │ ┌───▼───┐ │       │ ┌───▼───┐ │       │ ┌───▼───┐ │
    │ │Python │ │       │ │Python │ │       │ │Python │ │
    │ │API    │ │       │ │API    │ │       │ │API    │ │
    │ └───┬───┘ │       │ └───┬───┘ │       │ └───┬───┘ │
    │     │     │       │     │     │       │     │     │
    │ ┌───▼───┐ │       │ ┌───▼───┐ │       │ ┌───▼───┐ │
    │ │Go gRPC│ │       │ │Go gRPC│ │       │ │Go gRPC│ │
    │ │µsvc   │ │       │ │µsvc   │ │       │ │µsvc   │ │
    │ └───────┘ │       │ └───────┘ │       │ └───────┘ │
    └─────┬─────┘       └─────┬─────┘       └─────┬─────┘
          │                   │                   │
          │    NetworkPolicy: deny cross-tenant   │
          │                   │                   │
    ┌─────▼───────────────────▼───────────────────▼─────┐
    │              Shared Services Namespace              │
    │                                                     │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
    │  │ Kafka    │  │ Postgres │  │ Elastic- │         │
    │  │ (events) │  │ (RDS)    │  │ search   │         │
    │  └──────────┘  └──────────┘  └──────────┘         │
    │                                                     │
    │  All connections: mTLS via Istio                    │
    │  Data: encrypted at rest (KMS)                     │
    │  Indices: per-tenant (novasec-tenant-a-*)          │
    └─────────────────────────────────────────────────────┘
```

## Iron Legion Security Overlay

Three JSA agents monitor and enforce security across the NovaSec Cloud cluster:

```
┌─────────────────────────────────────────────────────────────────┐
│                  POLICY ENFORCEMENT LAYERS                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  LAYER 1: CI/CD (JSA-DevSec)                                   │
│  ─────────────────────────────                                  │
│  GitHub Actions → Trivy + Semgrep + Gitleaks + Conftest         │
│  8 OPA policies validate every push                             │
│  Gate: HIGH+ findings block merge                               │
│                                                                  │
│  LAYER 2: Admission (Kyverno + Gatekeeper)                      │
│  ──────────────────────────────────────────                     │
│  7 Kyverno ClusterPolicies (Enforce mode)                       │
│  4 Gatekeeper ConstraintTemplates + Constraints                 │
│  Gate: Non-compliant resources rejected at API server           │
│                                                                  │
│  LAYER 3: Runtime (JSA-InfraSec)                                │
│  ────────────────────────────────                               │
│  Falco DaemonSet: 6 custom rules + MITRE ATT&CK mapping        │
│  Alert → Rank → Response pipeline                               │
│  Gate: C-rank actions require JADE approval                     │
│                                                                  │
│  LAYER 4: Compliance (JSA-SecOps)                               │
│  ─────────────────────────────────                              │
│  Weekly scan-and-map reports                                    │
│  Evidence collection for 3PAO                                   │
│  OSCAL machine-readable SSP                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow: Finding → Resolution

```
1. Scanner detects finding
   │
2. Finding classified by type (SQLi, CVE, misconfig, etc.)
   │
3. Map to NIST 800-53 control (SI-2, AC-6, etc.)
   │
4. Assign Iron Legion rank (E/D/C/B/S)
   │
5. Route by rank:
   ├── E-rank → JSA auto-fix (no approval)
   ├── D-rank → JSA auto-fix + log
   ├── C-rank → JADE reviews and approves/denies
   ├── B-rank → Human review + JADE recommendation
   └── S-rank → Executive decision
   │
6. Remediation applied
   │
7. Evidence captured for compliance record
```

## AWS Infrastructure

| Service | Purpose | NIST Control |
|---------|---------|-------------|
| EKS | Multi-tenant Kubernetes | CM-6, AC-6 |
| RDS (PostgreSQL) | Metadata, tenant config | SC-28, SC-8 |
| S3 | Evidence storage, audit logs | AU-9, SC-28 |
| KMS | Encryption key management | SC-12, SC-28 |
| CloudWatch | Platform-level logging | AU-2, SI-4 |
| GuardDuty | AWS-level threat detection | SI-4 |
| WAF | Web application firewall | SC-7 |
| ACM | TLS certificate management | SC-8 |
