# CM — Configuration Management

## CM-2: Baseline Configuration

**Requirement**: Develop, document, and maintain a current baseline configuration of the information system.

**Implementation**:
- All Kubernetes manifests tracked in Git — Git history IS the baseline
- `automation/kubernetes/` contains the declared-state manifests (deployment, service, networkpolicy, rbac, namespace)
- Any drift from declared state detected by JSA-InfraSec
- Infrastructure changes require PR review + CI security scan pass before merge

**Evidence**:
- `automation/kubernetes/` — Baseline Kubernetes manifests
- Git history — Full change audit trail
- `.github/workflows/fedramp-compliance.yml` — Gate that validates baseline before merge

**Iron Legion Mapping**:
- **JSA-DevSec**: Validates manifests against baseline before deployment
- **JSA-InfraSec**: Detects runtime drift from baseline

---

## CM-6: Configuration Settings

**Requirement**: Establish and document configuration settings for IT products using security configuration checklists.

**Implementation**:
- OPA/Gatekeeper constraints enforce security configuration requirements at admission
- Kyverno ClusterPolicies enforce pod security, resource limits, image policies
- Conftest validates configuration settings in CI before deployment
- CIS Kubernetes Benchmark checks via kube-bench

**Configuration Requirements Enforced**:
| Setting | Policy | Tool |
|---------|--------|------|
| Non-root containers | `require-run-as-nonroot` | Kyverno |
| Drop all capabilities | `require-drop-all` | Kyverno |
| Resource limits | `require-resource-limits` | Kyverno |
| Trusted registries | `restrict-image-registries` | Kyverno |
| No privilege escalation | `disallow-privilege-escalation` | Kyverno |
| No host networking | `disallow-host-namespaces` | Kyverno |
| Read-only rootfs | `require-readonly-rootfs` | Kyverno |

**Evidence**:
- `automation/policies/kyverno/` — ClusterPolicy definitions
- `automation/policies/conftest/fedramp-controls.rego` — CI-time configuration checks
- `automation/policies/gatekeeper/` — Admission constraints

**Iron Legion Mapping**:
- **JSA-DevSec**: Validates configurations pre-deploy with Conftest + scanners
- **JSA-InfraSec**: Enforces configurations at runtime via admission controllers

---

## CM-8: Information System Component Inventory

**Requirement**: Develop and document an inventory of information system components.

**Implementation**:
- Kubernetes API provides real-time component inventory (pods, services, deployments, configmaps, secrets)
- Container images tracked with Trivy scan results (SBOM generation)
- `scan-and-map.py` enumerates components and maps to NIST controls
- Git tracks all infrastructure-as-code components

**Evidence**:
- `automation/scanning/scan-and-map.py` — Component enumeration
- `evidence/scan-reports/trivy-scan.json` — Container image inventory
- `automation/kubernetes/` — Declared component manifests
