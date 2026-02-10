# NovaSec Cloud — Control Coverage Matrix

NIST 800-53 → Iron Legion Component → Policy File → Evidence Artifact

## Priority Controls (8 of 323)

### AC-2: Account Management

| Requirement | Iron Legion Component | Policy File | Evidence |
|-------------|----------------------|-------------|----------|
| Individual account assignment | OPA: AC-2 policy | `policies/opa/ac2_account_management.rego` | Conftest CI results |
| SA token management | OPA: AC-2 policy | `policies/opa/ac2_account_management.rego` | Conftest CI results |
| Tenant-scoped accounts | Kyverno: tenant isolation | `policies/kyverno/enforce-tenant-isolation.yaml` | Kyverno PolicyReport |
| Account naming conventions | OPA: AC-2 policy | `policies/opa/ac2_account_management.rego` | Conftest CI results |
| Account lifecycle | Gatekeeper: tenant isolation | `policies/gatekeeper/constraints/tenant-isolation-constraint.yaml` | Gatekeeper audit logs |

### AC-6: Least Privilege

| Requirement | Iron Legion Component | Policy File | Evidence |
|-------------|----------------------|-------------|----------|
| Non-root containers | OPA + Kyverno + Gatekeeper | `ac6_least_privilege.rego`, `require-least-privilege.yaml`, `k8s-least-privilege.yaml` | CI + admission logs |
| Drop ALL capabilities | OPA + Kyverno | `ac6_least_privilege.rego`, `require-least-privilege.yaml` | CI + admission logs |
| No privileged mode | Kyverno | `policies/kyverno/block-privileged-containers.yaml` | Admission audit |
| No host namespaces | OPA + Kyverno | `ac6_least_privilege.rego`, `block-privileged-containers.yaml` | CI + admission logs |
| Read-only rootfs | OPA + Kyverno | `ac6_least_privilege.rego`, `require-least-privilege.yaml` | CI + admission logs |

### AU-2: Audit Events

| Requirement | Iron Legion Component | Policy File | Evidence |
|-------------|----------------------|-------------|----------|
| Falco monitoring | OPA: AU-2 policy | `policies/opa/au2_audit_events.rego` | Falco alert logs |
| Audit sidecar | OPA: AU-2 policy | `policies/opa/au2_audit_events.rego` | Pod spec audit |
| Log format standardization | OPA + Kyverno | `au2_audit_events.rego`, `require-audit-logging.yaml` | Label inventory |
| Namespace audit level | OPA: AU-2 policy | `policies/opa/au2_audit_events.rego` | Namespace annotations |

### CM-6: Configuration Settings

| Requirement | Iron Legion Component | Policy File | Evidence |
|-------------|----------------------|-------------|----------|
| Resource limits | OPA + Kyverno | `cm6_configuration_settings.rego`, `require-resource-limits.yaml` | CI + admission logs |
| Required labels | OPA: CM-6 policy | `policies/opa/cm6_configuration_settings.rego` | Conftest CI results |
| Immutable image tags | OPA: CM-6 policy | `policies/opa/cm6_configuration_settings.rego` | CI results |
| Approved registries | OPA: CM-6 + SI-2 | `cm6_configuration_settings.rego`, `si2_flaw_remediation.rego` | CI results |

### SC-7: Boundary Protection

| Requirement | Iron Legion Component | Policy File | Evidence |
|-------------|----------------------|-------------|----------|
| Default-deny NetworkPolicy | OPA + Kyverno + Gatekeeper | `sc7_boundary_protection.rego`, `enforce-network-boundaries.yaml`, `k8s-network-boundaries.yaml` | CI + admission + GK audit |
| Block NodePort | OPA + Kyverno + Gatekeeper | Same as above | CI + admission logs |
| Tenant namespace isolation | OPA + Kyverno | `sc7_boundary_protection.rego`, `enforce-network-boundaries.yaml` | NetworkPolicy audit |
| No hostPort | OPA: SC-7 policy | `policies/opa/sc7_boundary_protection.rego` | Conftest CI results |

### SC-8: Transmission Confidentiality

| Requirement | Iron Legion Component | Policy File | Evidence |
|-------------|----------------------|-------------|----------|
| Ingress TLS | OPA + Kyverno + Gatekeeper | `sc8_transmission_confidentiality.rego`, `require-tls-everywhere.yaml`, `k8s-require-tls.yaml` | CI + admission + GK audit |
| Service mTLS | OPA + Kyverno + Gatekeeper | Same as above | Istio mTLS report |
| No plaintext ports | OPA: SC-8 policy | `policies/opa/sc8_transmission_confidentiality.rego` | Conftest CI results |
| Service mesh sidecar | OPA: SC-8 policy | `policies/opa/sc8_transmission_confidentiality.rego` | Pod spec audit |

### SI-2: Flaw Remediation

| Requirement | Iron Legion Component | Policy File | Evidence |
|-------------|----------------------|-------------|----------|
| Pinned image tags | OPA: SI-2 policy | `policies/opa/si2_flaw_remediation.rego` | Conftest CI results |
| Approved registry | OPA: SI-2 + CM-6 | `si2_flaw_remediation.rego`, `cm6_configuration_settings.rego` | CI results |
| Trivy scan annotation | OPA: SI-2 policy | `policies/opa/si2_flaw_remediation.rego` | Trivy scan reports |
| CVE scanning | JSA-DevSec: Trivy | `jsa-devsec/trivy-config.yaml` | Trivy JSON reports |
| SAST scanning | JSA-DevSec: Semgrep | `jsa-devsec/semgrep-rules.yaml` | Semgrep JSON reports |

### SI-4: System Monitoring

| Requirement | Iron Legion Component | Policy File | Evidence |
|-------------|----------------------|-------------|----------|
| Falco runtime detection | JSA-InfraSec: Falco | `jsa-infrasec/falco-rules.yaml` | Falco alert logs |
| Prometheus metrics | OPA: SI-4 policy | `policies/opa/si4_system_monitoring.rego` | Prometheus targets |
| Log collection | OPA: SI-4 policy | `policies/opa/si4_system_monitoring.rego` | Fluentbit/Vector config |
| Health probes | OPA: SI-4 policy | `policies/opa/si4_system_monitoring.rego` | Pod spec audit |
| Alert → response mapping | JSA-InfraSec | `jsa-infrasec/runtime-policies.yaml` | Response action logs |

## Evidence Generation

Evidence is generated automatically by:
1. **CI pipeline** (`fedramp-ci.yml`) — Trivy, Semgrep, Gitleaks, Conftest results
2. **Admission control** — Kyverno PolicyReports, Gatekeeper audit logs
3. **Runtime** — Falco alerts, Prometheus metrics
4. **Compliance reports** (`compliance-report.yml`) — Weekly aggregated reports
5. **Evidence collector** (`evidence-collector.sh`) — Timestamped evidence packages
