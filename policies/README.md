# Policy-as-Code — Anthra-FedRAMP

Admission control and CI/CD gate policies for FedRAMP Moderate authorization. All policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) and validated with [Conftest](https://www.conftest.dev/).

## Quick Start

```bash
# Validate all infrastructure manifests against policies
conftest test infrastructure/*.yaml --policy policies/conftest/

# Validate a single file
conftest test infrastructure/api-deployment.yaml --policy policies/conftest/

# Run in CI (non-zero exit on deny)
conftest test infrastructure/*.yaml --policy policies/conftest/ --output json
```

## Policy Inventory

| Policy | Controls | What It Enforces |
|--------|----------|------------------|
| `network-boundary.rego` | NIST SC-7, SC-7(4) | Prohibits NodePort/LoadBalancer — all ingress through TLS-terminated Ingress controller |
| `resource-limits.rego` | NIST CM-2 | Requires CPU/memory limits on all containers (prevents resource exhaustion) |
| `image-security.rego` | CIS 5.1.1, NIST SA-10, SLSA L3 | Trusted registries, no `:latest` tag, image signing for production |
| `secrets-management.rego` | CIS 5.4.1, NIST SC-28, PCI-DSS 3.4 | No secrets in env vars, no hardcoded credentials, volume permissions |
| `compliance-controls.rego` | SOC 2 CC6.1, PCI-DSS 6.4.1, GDPR Art.32 | Audit labels, data classification, change management, data residency |
| `cicd-security.rego` | SLSA L4, NIST SSDF, SOC 2 CC7.2 | Pipeline gates — SAST, SCA, secret scanning, signed commits, provenance |

## Compliance Framework Coverage

```
NIST 800-53 Rev 5    AC-2, CM-2, CM-6, SC-7, SC-28, SA-10, SI-2, SI-4, IA-5
FedRAMP Moderate     AC-2, AC-6, CM-2, CM-6, CM-7, SC-7, SC-8, SC-28, SI-2, SI-4
CIS Kubernetes 1.8   5.1.1, 5.1.2, 5.1.3, 5.1.5, 5.2.1–5.2.11, 5.3.2, 5.4.1, 5.4.2
PCI-DSS v4.0         Req 1.2, 2.2, 3.4, 6.2, 6.3, 7.2, 10.1
SOC 2 Type II        CC6.1, CC6.2, CC6.6, CC7.2, CC8.1, CC9.1
SLSA                 Source L3, Build L3–L4, Provenance L3
```

## Policy Types

| Rego Rule | Behavior | Use Case |
|-----------|----------|----------|
| `deny` | Blocks deployment (non-zero exit) | Security violations, compliance hard gates |
| `warn` | Logs warning (zero exit) | Best-practice advisories, soft gates |

## Architecture

```
policies/
└── conftest/                     # OPA/Conftest policy-as-code
    ├── network-boundary.rego     # Network segmentation (SC-7)
    ├── resource-limits.rego      # Resource management (CM-2)
    ├── image-security.rego       # Supply chain security (SA-10, SLSA)
    ├── secrets-management.rego   # Credential protection (SC-28, IA-5)
    ├── compliance-controls.rego  # Multi-framework compliance gates
    └── cicd-security.rego        # CI/CD pipeline security gates
```

These policies run at two stages:

1. **Pre-commit / CI gate** — `conftest test` validates manifests before merge
2. **Admission control** — OPA Gatekeeper enforces a subset at deploy time (see `infrastructure/`)

## Adding a New Policy

```rego
# policies/conftest/my-new-policy.rego
package main  # or package kubernetes.admission.security.<domain>

# Map to a compliance control
# NIST 800-53 XX-N: CONTROL NAME

deny[msg] {
    # Match the resource kind
    input.kind == "Deployment"
    # Check the condition
    <condition>
    # Return a clear, actionable message with the control reference
    msg := sprintf("...", [...])
}
```

Run `conftest verify --policy policies/conftest/` to validate policy syntax.
