# NovaSec Cloud — Engagement Overview

## Client Profile

**Company:** NovaSec Cloud, Inc.
**Industry:** SaaS Security Monitoring (SIEM/SOAR)
**Target Market:** Federal agencies (DHS, DoD, FBI)
**Authorization Level:** FedRAMP Moderate
**Contract Driver:** DHS centralized log aggregation and threat detection

## Technology Stack

- **Compute:** Amazon EKS (multi-tenant Kubernetes)
- **Frontend:** React SPA with server-side rendering
- **APIs:** Python (FastAPI) + Go (gRPC microservices)
- **Search/Analytics:** Elasticsearch (per-tenant indices)
- **Database:** PostgreSQL (RDS, encrypted at rest)
- **Storage:** S3 (evidence, logs, audit trails)
- **Messaging:** Kafka (event streaming between tenants and services)
- **Service Mesh:** Istio (mTLS between all services)
- **Monitoring:** Prometheus + Grafana + Falco

## Multi-Tenant Architecture

NovaSec Cloud serves multiple federal agencies from a shared EKS cluster.
Tenant isolation is enforced at every layer:

| Layer | Isolation Mechanism | NIST Control |
|-------|-------------------|-------------|
| Namespace | Dedicated namespace per tenant | AC-2, SC-7 |
| Network | Default-deny NetworkPolicy | SC-7 |
| Data | Per-tenant Elasticsearch indices | SC-28 |
| Encryption | mTLS between all services | SC-8 |
| RBAC | Tenant-scoped ServiceAccounts | AC-6 |
| Monitoring | Per-tenant audit streams | AU-2 |

## Engagement Phases

### Phase 1: Gap Assessment
- Scan target application (DVWA as stand-in) with Trivy, Semgrep, Gitleaks
- Map findings to NIST 800-53 controls
- Identify gaps in 8 priority controls
- Deliverable: Gap assessment report

### Phase 2: Remediation Planning
- Prioritize findings by Iron Legion rank (E → S)
- Define remediation timeline
- Assign automation level per finding
- Deliverable: POA&M with rank-based SLAs

### Phase 3: Pre-Deployment Hardening (JSA-DevSec)
- OPA/Rego policies for CI/CD gating (8 policies)
- Kyverno admission policies (7 policies)
- Gatekeeper constraints (4 template/constraint pairs)
- Semgrep SAST rules, Gitleaks secret detection
- Deliverable: Policy-as-code repository

### Phase 4: Runtime Enforcement (JSA-InfraSec)
- Falco custom rules for NovaSec Cloud threat model
- Runtime policy mapping (alert → rank → response)
- NetworkPolicy enforcement for tenant isolation
- Deliverable: Runtime security configuration

### Phase 5: Compliance Documentation
- OSCAL-formatted SSP (machine-readable)
- Control-by-control coverage matrix
- Evidence artifacts for each implemented control
- Deliverable: SSP + evidence package

### Phase 6: 3PAO Preparation
- Evidence collection automation
- Compliance report generation (weekly)
- Audit trail completeness verification
- Deliverable: 3PAO-ready evidence package
