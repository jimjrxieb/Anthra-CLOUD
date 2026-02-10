# AC — Access Control

## AC-2: Account Management

**Requirement**: Manage information system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts.

**Implementation**:
- Kubernetes RBAC policies define service accounts with minimum required permissions
- Service accounts are scoped to specific namespaces
- JSA-DevSec scans RBAC manifests pre-deployment, rejects over-permissive roles
- JSA-InfraSec monitors for privilege escalation at runtime

**Evidence**:
- `automation/kubernetes/rbac.yaml` — RBAC templates with least-privilege roles
- `automation/policies/kyverno/require-sa-token-automount.yaml` — Block default SA token mounting
- `evidence/scan-reports/` — Scan results showing RBAC review

**Iron Legion Mapping**:
- **JSA-DevSec**: Scans RBAC manifests before deployment (E-D rank)
- **JSA-InfraSec**: Monitors SA usage, detects escalation (D-C rank)
- **JADE**: Approves RBAC changes above D-rank

---

## AC-3: Access Enforcement

**Requirement**: Enforce approved authorizations for logical access to information and system resources.

**Implementation**:
- Kubernetes RBAC enforces role-based access to API resources
- Namespace isolation prevents cross-tenant access
- NetworkPolicy enforces network-level access control
- OPA/Gatekeeper constraints enforce admission policies

**Evidence**:
- `automation/kubernetes/rbac.yaml` — Role/RoleBinding definitions
- `automation/kubernetes/networkpolicy.yaml` — Default deny + explicit allow
- `automation/policies/gatekeeper/` — Admission constraints

**Iron Legion Mapping**:
- **JSA-DevSec**: Validates RBAC + NetworkPolicy exist pre-deploy
- **JSA-InfraSec**: Enforces policies at admission, monitors violations

---

## AC-6: Least Privilege

**Requirement**: Employ the principle of least privilege, allowing only authorized accesses needed to accomplish assigned tasks.

**Implementation**:
- Pod security contexts: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`
- Capabilities dropped: `ALL`, only add back what's needed
- Read-only root filesystem where possible
- Pod Security Standards (PSS) `restricted` profile enforced via namespace labels

**Evidence**:
- `automation/remediation/pod-security-context.yaml` — Hardened security contexts
- `automation/policies/kyverno/require-run-as-nonroot.yaml` — Enforce non-root
- `automation/policies/kyverno/require-drop-all.yaml` — Enforce capability drop

**Iron Legion Mapping**:
- **JSA-DevSec**: Scans manifests for privilege violations (E-rank auto-fix)
- **JSA-InfraSec**: Blocks privileged pods at admission (D-rank)

---

## AC-17: Remote Access

**Requirement**: Establish usage restrictions, configuration/connection requirements, and implementation guidance for remote access.

**Implementation**:
- Kubernetes API server access via kubeconfig with RBAC
- No direct node SSH access in production
- kubectl access audited via Kubernetes audit logs
- GitHub Actions uses OIDC federation (no long-lived credentials)

**Evidence**:
- `automation/kubernetes/rbac.yaml` — API access roles
- `automation/remediation/audit-logging.yaml` — API audit configuration
