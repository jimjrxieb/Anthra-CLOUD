# SC — System and Communications Protection

## SC-7: Boundary Protection

**Requirement**: Monitor and control communications at the external boundary of the system and at key internal boundaries within the system.

**Implementation**:
- **Kubernetes NetworkPolicy**: Default deny all ingress/egress, explicit allow for required flows
- **Namespace Isolation**: DVWA deployed in dedicated namespace with PSS labels
- **Ingress Control**: Only port 80 exposed via Service, no host networking
- **Egress Control**: Only database (MariaDB) egress allowed from DVWA pods
- **Kyverno Policy**: Enforces NetworkPolicy existence for all namespaces

**Network Flow Rules**:
| Source | Destination | Port | Action |
|--------|-------------|------|--------|
| External | DVWA Service | 80/TCP | Allow |
| DVWA Pod | MariaDB Pod | 3306/TCP | Allow |
| DVWA Pod | DNS | 53/UDP | Allow |
| Any | Any | * | Deny (default) |

**Evidence**:
- `automation/kubernetes/networkpolicy.yaml` — NetworkPolicy manifests
- `automation/remediation/network-policies.yaml` — Network policy templates
- `automation/policies/conftest/fedramp-controls.rego` — Policy validation

**Iron Legion Mapping**:
- **JSA-DevSec**: Validates NetworkPolicy exists in manifests pre-deploy
- **JSA-InfraSec**: Monitors network flows, detects policy gaps at runtime

---

## SC-28: Protection of Information at Rest

**Requirement**: Protect the confidentiality and integrity of information at rest.

**Implementation**:
- **Database**: MariaDB data volume can be encrypted via storage class (EBS encryption on AWS)
- **Kubernetes Secrets**: Stored encrypted in etcd (encryption-at-rest configuration)
- **Container Images**: Stored in authenticated registry (ghcr.io)
- **Evidence Files**: Stored in Git (integrity via SHA hashes)

**Status**: Partially implemented — encryption at rest depends on infrastructure provider configuration.

**Evidence**:
- `automation/kubernetes/deployment.yaml` — Volume configuration
- Infrastructure provider documentation for encryption settings
