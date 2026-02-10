# AU — Audit and Accountability

## AU-2: Audit Events

**Requirement**: Determine that the information system is capable of auditing defined events.

**Implementation**:
- Kubernetes audit logging enabled with comprehensive audit policy
- API server requests logged: create, update, delete, patch on security-sensitive resources
- Container stdout/stderr captured by cluster logging
- GitHub Actions workflow logs retained for CI/CD audit trail
- Falco generates real-time syscall-level audit events

**Auditable Events**:
| Event | Source | Retention |
|-------|--------|-----------|
| API server requests | K8s audit log | 90 days |
| Pod creation/deletion | K8s events + audit | 90 days |
| Policy violations | OPA/Kyverno admission logs | 90 days |
| Security scan results | GitHub Actions artifacts | 90 days |
| Syscall anomalies | Falco alerts | 30 days |
| Configuration changes | Git history | Permanent |

**Evidence**:
- `automation/remediation/audit-logging.yaml` — Audit policy configuration
- `.github/workflows/fedramp-compliance.yml` — CI/CD audit trail
- `evidence/scan-reports/` — Historical scan artifacts

**Iron Legion Mapping**:
- **JSA-DevSec**: Validates audit logging is configured in manifests pre-deploy
- **JSA-InfraSec**: Monitors that audit logs are flowing at runtime
- **JADE**: Aggregates findings for AU control evidence

---

## AU-3: Content of Audit Records

**Requirement**: Audit records contain information about what type of event occurred, when it occurred, where it occurred, the source, the outcome, and the identity of individuals/subjects.

**Implementation**:
- Kubernetes audit log format includes:
  - `verb` (what): create, update, delete, patch
  - `requestReceivedTimestamp` (when): ISO 8601 timestamp
  - `sourceIPs` (where/who): Client IP address
  - `user.username` (identity): Authenticated user/SA
  - `objectRef` (what resource): Namespace, resource, name
  - `responseStatus.code` (outcome): Success/failure code
- Falco alerts include: rule name, priority, output fields, container info, process details

**Evidence**:
- `automation/remediation/audit-logging.yaml` — Audit policy defining captured fields
- Sample audit log entries in `evidence/scan-reports/`
