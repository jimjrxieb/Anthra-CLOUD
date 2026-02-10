# GP-Copilot — Iron Legion Security Overlay

This directory contains the GuidePoint Security Iron Legion overlay that makes NovaSec Cloud FedRAMP Moderate compliant.

**The NovaSec Cloud app (in `../api/`, `../services/`, `../ui/`) ships with real security problems. Everything in this directory is what fixes them.**

---

## What's Here

| Directory | Purpose | Phase |
|-----------|---------|-------|
| `policies/opa/` | 8 OPA/Rego policies — one per priority NIST control | CI (Conftest) |
| `policies/kyverno/` | 7 Kyverno ClusterPolicies — admission control | Deploy-time |
| `policies/gatekeeper/` | 4 Gatekeeper constraint template/constraint pairs | Deploy-time |
| `jsa-devsec/` | Pre-deployment scanning configs (Trivy, Semgrep, Gitleaks) | CI/CD |
| `jsa-infrasec/` | Runtime enforcement (Falco rules, escalation policies) | Runtime |
| `jsa-secops/` | Compliance reporting (scan-and-map, evidence collector) | Continuous |
| `oscal/` | NIST OSCAL machine-readable compliance (SSP, components) | Audit |
| `docs/` | Engagement documentation (architecture, gap assessment) | Reference |

## 8 Priority Controls (FedRAMP Moderate)

| Control | Name | OPA | Kyverno | Gatekeeper | Falco |
|---------|------|-----|---------|------------|-------|
| AC-2 | Account Management | Y | Y | Y | - |
| AC-6 | Least Privilege | Y | Y | Y | - |
| AU-2 | Audit Events | Y | Y | - | Y |
| CM-6 | Configuration Settings | Y | Y | - | - |
| SC-7 | Boundary Protection | Y | Y | Y | - |
| SC-8 | Transmission Confidentiality | Y | Y | Y | - |
| SI-2 | Flaw Remediation | Y | - | - | - |
| SI-4 | System Monitoring | Y | Y | - | Y |

## Usage

```bash
# Validate OPA policies parse
conftest verify --policy policies/opa/

# Scan insecure K8s manifests against policies
conftest test ../infrastructure/ --policy policies/opa/

# Run full compliance scan
python jsa-secops/scan-and-map.py \
  --client-name "NovaSec Cloud" \
  --target-dir ../api/ \
  --dry-run

# Collect evidence for 3PAO
./jsa-secops/evidence-collector.sh ../evidence/
```

## Iron Legion Agents

| Agent | Role | Rank Range |
|-------|------|------------|
| JSA-DevSec | Pre-deployment scanning | E-D |
| JSA-InfraSec | Runtime enforcement | D-C |
| JSA-SecOps | Compliance reporting | D-C |
| JADE | Supervisor (approve/escalate) | C (max) |
