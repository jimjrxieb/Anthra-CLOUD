# NovaSec Cloud — FedRAMP Moderate Authorization

**Client:** NovaSec Cloud (multi-tenant SaaS security monitoring platform)
**Objective:** FedRAMP Moderate authorization to sell to DHS
**Baseline:** NIST 800-53 Rev 5 — 323 controls
**Engagement by:** GuidePoint Security Engineering — Iron Legion Platform

---

## What Is NovaSec Cloud?

A smaller Splunk for federal agencies — centralized log aggregation, threat detection, and compliance dashboards. Multi-tenant (DHS, DoD, FBI each get isolated namespaces), runs on EKS.

**The problem:** NovaSec shipped fast and insecure. The application has SQL injection, XSS, command injection, hardcoded credentials, and zero access control. The Kubernetes manifests run everything as root with no security contexts, no network policies, and no TLS.

**The fix:** GuidePoint's Iron Legion overlay (`GP-Copilot/`) — automated policy enforcement across the full lifecycle: CI/CD scanning, admission control, runtime detection, and continuous compliance reporting.

---

## Quick Start

```bash
# Start the insecure app
docker compose up -d

# API health check
curl http://localhost:8080/api/health

# UI dashboard
open http://localhost:3000
```

## The Vulnerabilities

Every endpoint is deliberately insecure, mirroring DVWA patterns in a modern Python/Go stack:

```bash
# SQL Injection — dump all tenant logs
curl "http://localhost:8080/api/logs?tenant_id=1' OR '1'='1"

# Reflected XSS — script injection in search
curl "http://localhost:8080/api/search?q=<script>alert('xss')</script>"

# Command Injection — execute arbitrary commands
curl -X POST http://localhost:8080/api/diagnostic \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1; cat /etc/passwd"}'

# Path Traversal — read system files
curl "http://localhost:8080/api/reports?file=../../../etc/passwd"

# Debug endpoint — leaks all environment variables
curl http://localhost:8080/api/debug

# Brute force login — no rate limiting, MD5 passwords
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### Vulnerability Map

| Endpoint | Vulnerability | DVWA Equivalent | NIST Gap |
|----------|--------------|-----------------|----------|
| `GET /api/logs?tenant_id=` | SQL Injection | sqli/low | SI-2 |
| `GET /api/search?q=` | Reflected XSS | xss_r/low | SI-2 |
| `POST /api/alerts` | Stored XSS | xss_s/low | SI-2 |
| `POST /api/diagnostic` | Command Injection | exec/low | SI-2 |
| `POST /api/config/upload` | Unrestricted Upload | upload/low | CM-6 |
| `POST /api/auth/login` | No rate limit, MD5 | brute/low | AC-2, IA-5 |
| `GET /api/reports?file=` | Path Traversal | fi/low | AC-3 |
| `POST /api/tenant/settings` | No CSRF token | csrf/low | SC-7 |
| All endpoints | No auth middleware | authbypass | AC-2, AC-6 |
| `api/main.py:28` | Hardcoded DB creds | — | IA-5 |
| `services/main.go` | No validation, no auth | — | CM-6, SI-2 |

### Insecure K8s Manifests (`infrastructure/`)

| What's Wrong | Control Gap |
|-------------|------------|
| Runs as root, no `securityContext` | AC-6 |
| No `resources.limits` | CM-6 |
| No NetworkPolicy | SC-7 |
| NodePort services exposed | SC-7 |
| No TLS on Ingress | SC-8 |
| `:latest` image tags | SI-2 |
| Default ServiceAccount | AC-2 |
| No liveness/readiness probes | SI-4 |

---

## The Fix: GP-Copilot Iron Legion Overlay

Everything in `GP-Copilot/` is what makes this FedRAMP-compliant:

```
GP-Copilot/
├── policies/opa/           8 OPA/Rego policies (CI via Conftest)
├── policies/kyverno/       7 Kyverno admission policies
├── policies/gatekeeper/    4 Gatekeeper constraint pairs
├── jsa-devsec/             Pre-deploy scanning (Trivy, Semgrep, Gitleaks)
├── jsa-infrasec/           Runtime enforcement (Falco rules)
├── jsa-secops/             Compliance reporting (scan-and-map)
├── oscal/                  NIST OSCAL machine-readable compliance
└── docs/                   Engagement documentation
```

### Run the Policies Against Insecure Manifests

```bash
# OPA policies catch all infrastructure violations
conftest test infrastructure/ --policy GP-Copilot/policies/opa/

# Full compliance scan with NIST control mapping
python GP-Copilot/jsa-secops/scan-and-map.py \
  --client-name "NovaSec Cloud" \
  --target-dir api/ \
  --dry-run
```

### 8 Priority Controls

| Control | Name | What It Fixes |
|---------|------|---------------|
| **AC-2** | Account Management | Default ServiceAccount, no auth |
| **AC-6** | Least Privilege | Root containers, no RBAC |
| **AU-2** | Audit Events | No logging, no Falco |
| **CM-6** | Configuration Settings | No resource limits, no hardening |
| **SC-7** | Boundary Protection | No NetworkPolicy, NodePort exposure |
| **SC-8** | Transmission Confidentiality | No TLS, no mTLS |
| **SI-2** | Flaw Remediation | SQLi, XSS, command injection, :latest tags |
| **SI-4** | System Monitoring | No runtime detection, no probes |

---

## Architecture

```
NovaSec Cloud (the insecure app)
├── api/            Python FastAPI — 12 vulnerable endpoints
├── ui/             React dashboard — renders XSS
├── services/       Go log-ingest — no validation
├── infrastructure/ K8s manifests — no security controls
└── target-app/     DVWA (reference vulnerable app)

GP-Copilot (the fix)
├── CI/CD scanning      → Catch before merge
├── Admission control   → Block at deploy
├── Runtime enforcement → Detect in production
└── Compliance reports  → Evidence for 3PAO
```

---

## Directory Structure

```
FedRAMP/
├── README.md                    ← You are here
├── docker-compose.yml           ← Start the insecure app
├── api/                         ← Python FastAPI (VULNERABLE)
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py                  ← 12 vuln endpoints
├── ui/                          ← React dashboard (minimal)
│   ├── Dockerfile
│   ├── package.json
│   ├── index.html
│   └── src/
├── services/                    ← Go log-ingest (VULNERABLE)
│   ├── Dockerfile
│   ├── go.mod
│   └── main.go
├── infrastructure/              ← K8s manifests (INSECURE)
│   ├── namespace.yaml
│   ├── api-deployment.yaml
│   ├── ui-deployment.yaml
│   ├── log-ingest-deployment.yaml
│   ├── db-deployment.yaml
│   ├── services.yaml
│   └── ingress.yaml
├── target-app/                  ← DVWA (reference)
├── GP-Copilot/                  ← Iron Legion overlay (THE FIX)
│   ├── policies/
│   ├── jsa-devsec/
│   ├── jsa-infrasec/
│   ├── jsa-secops/
│   ├── oscal/
│   └── docs/
└── .github/workflows/           ← CI/CD pipelines
```

---

## Iron Legion Agents

| Agent | Phase | What It Does | Rank |
|-------|-------|-------------|------|
| **JSA-DevSec** | Pre-deploy | Trivy, Semgrep, Gitleaks, Conftest | E-D |
| **JSA-InfraSec** | Runtime | Falco, NetworkPolicy, pod isolation | D-C |
| **JSA-SecOps** | Reporting | scan-and-map, evidence-collector | D-C |
| **JADE** | Supervisor | Approve C-rank, escalate B-S to human | C (max) |
