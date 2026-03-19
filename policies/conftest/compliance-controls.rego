package kubernetes.admission.compliance

# UNDERSTANDING: Compliance isn't checkbox theater - it's risk management
# Each control maps to specific breach patterns
# Audit trails enable forensics and accountability
#
# INPUT: Raw Kubernetes YAML (conftest format — input IS the resource)

import future.keywords.contains
import future.keywords.if
import future.keywords.in

metadata := {
    "policy": "compliance-enforcement",
    "version": "1.1.0",
    "frameworks": ["SOC2-TypeII", "PCI-DSS-v4", "HIPAA", "ISO27001", "GDPR"],
    "audit_scope": "full-lifecycle-compliance",
    "last_review": "2026-02-26"
}

# --- Kind guards ---
# Resources that should have compliance labels (workloads + stateful)
labelable_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "Service", "ConfigMap"}

is_labelable {
    labelable_kinds[input.kind]
}

# CRITICAL: Resource labeling for audit trails
# COMPLIANCE: SOC2 CC6.1, ISO27001 A.8.1, GDPR Art.30
# THREAT: Audit gaps, compliance violations
deny[msg] {
    is_labelable
    not has_required_labels
    msg := sprintf("%v '%v' missing required compliance labels: owner, cost-center, data-classification",
                   [input.kind, input.metadata.name])
}

has_required_labels {
    input.metadata.labels.owner
    input.metadata.labels["cost-center"]
    input.metadata.labels["data-classification"]
}

# HIGH: Data classification enforcement
# COMPLIANCE: GDPR Art.32, HIPAA §164.312, PCI-DSS 3.0
# THREAT: Unauthorized data access, regulatory fines
deny[msg] {
    is_labelable
    data_class := input.metadata.labels["data-classification"]
    data_class in ["pii", "phi", "cardholder-data"]
    not has_encryption_at_rest
    msg := sprintf("%v '%v' with '%v' data must have encryption at rest",
                   [input.kind, input.metadata.name, data_class])
}

has_encryption_at_rest {
    input.metadata.annotations["encryption.ghostprotocol.io/at-rest"] == "true"
}

# HIGH: Audit logging requirements
# COMPLIANCE: SOC2 CC7.2, PCI-DSS 10.2, HIPAA §164.312(b)
# THREAT: Security incident detection gaps
deny[msg] {
    is_labelable
    is_sensitive_resource
    not has_audit_logging_enabled
    msg := sprintf("%v '%v' is sensitive and must have audit logging enabled",
                   [input.kind, input.metadata.name])
}

is_sensitive_resource {
    input.metadata.labels["data-classification"] in ["restricted", "confidential"]
}

has_audit_logging_enabled {
    input.metadata.annotations["logging.ghostprotocol.io/audit-enabled"] == "true"
}

# HIGH: Retention policy enforcement
# COMPLIANCE: SOC2 A1.2, GDPR Art.17, PCI-DSS 3.1
# THREAT: Data retention violations, storage costs
warn[msg] {
    input.kind == "Secret"
    not input.metadata.annotations["retention.ghostprotocol.io/expiry-date"]
    msg := sprintf("Secret '%v' must have retention/expiry date annotation", [input.metadata.name])
}

# MEDIUM: Change management documentation (production only)
# COMPLIANCE: SOC2 CC8.1, ISO27001 A.12.1.2
# THREAT: Unauthorized changes, audit failures
deny[msg] {
    is_labelable
    is_production
    not has_change_ticket
    msg := sprintf("%v '%v' in production requires change ticket annotation",
                   [input.kind, input.metadata.name])
}

has_change_ticket {
    input.metadata.annotations["change.ghostprotocol.io/ticket-id"]
    input.metadata.annotations["change.ghostprotocol.io/approved-by"]
}

# MEDIUM: Environment segregation
# COMPLIANCE: PCI-DSS 6.4.1, SOC2 CC6.6
# THREAT: Dev/test data in production
deny[msg] {
    is_labelable
    is_production
    has_non_production_indicator
    msg := sprintf("%v '%v' in production cannot have dev/test/staging indicators",
                   [input.kind, input.metadata.name])
}

has_non_production_indicator {
    label_value := input.metadata.labels[_]
    label_value in ["dev", "test", "staging", "development"]
}

# LOW: Cost allocation tagging
# COMPLIANCE: FinOps best practices, SOC2 CC1.4
# THREAT: Budget overruns, resource waste
warn[msg] {
    is_labelable
    not input.metadata.labels["cost-center"]
    msg := sprintf("%v '%v' must have cost-center label for financial tracking",
                   [input.kind, input.metadata.name])
}

# HIGH: Data residency compliance
# COMPLIANCE: GDPR Art.44, CCPA, Data Sovereignty
# THREAT: Cross-border data transfer violations
deny[msg] {
    is_labelable
    data_class := input.metadata.labels["data-classification"]
    data_class in ["pii", "gdpr-protected"]
    region := input.metadata.labels["topology.kubernetes.io/region"]
    not is_compliant_region(region, data_class)
    msg := sprintf("Data class '%v' cannot be stored in region '%v'", [data_class, region])
}

is_compliant_region(region, data_class) {
    # EU data must stay in EU
    data_class == "gdpr-protected"
    startswith(region, "eu-")
}

is_compliant_region(region, data_class) {
    # US PII can be in US regions
    data_class == "pii"
    region in ["us-east-1", "us-west-2", "us-central-1"]
}

# MEDIUM: Backup and disaster recovery
# COMPLIANCE: SOC2 CC9.1, ISO27001 A.12.3
# THREAT: Data loss, business continuity failure
deny[msg] {
    is_stateful_resource
    not has_backup_policy
    msg := sprintf("%v '%v' must have backup policy annotation",
                   [input.kind, input.metadata.name])
}

is_stateful_resource {
    input.kind in ["StatefulSet", "PersistentVolumeClaim"]
}

has_backup_policy {
    input.metadata.annotations["backup.ghostprotocol.io/enabled"] == "true"
    input.metadata.annotations["backup.ghostprotocol.io/retention-days"]
}

# HIGH: Access control review
# COMPLIANCE: SOC2 CC6.2, ISO27001 A.9.2.1
# THREAT: Stale permissions, privilege creep
warn[msg] {
    input.kind in ["Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"]
    not has_access_review_date
    msg := sprintf("RBAC resource '%v' must have last-review-date annotation for access certification",
                   [input.metadata.name])
}

has_access_review_date {
    review_date := input.metadata.annotations["rbac.ghostprotocol.io/last-review-date"]
    is_recent_review(review_date)
}

is_recent_review(date_string) {
    # Simplified check - in production, use time.parse_rfc3339_ns
    date_string != ""
}

is_production {
    input.metadata.namespace in ["production", "prod", "live"]
}
