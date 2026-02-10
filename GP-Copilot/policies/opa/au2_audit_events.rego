package novasec.au2

# AU-2: Audit Events
# Ensures workloads have audit logging capability via Falco sidecars,
# audit annotations, and proper log format labels.

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.novasec.lib

metadata := {
    "policy": "au2-audit-events",
    "version": "1.0.0",
    "compliance": ["NIST-AU-2", "NIST-AU-3", "NIST-AU-12", "FedRAMP-MOD"],
    "risk_level": "HIGH",
    "author": "GuidePoint Security Engineering",
    "last_review": "2026-02-10",
}

# HIGH: Require Falco annotation or audit sidecar
# THREAT: Workloads without audit logging cannot be investigated during incidents
# COMPLIANCE: NIST AU-2 — determine auditable events
violation[{"msg": msg, "severity": "HIGH", "control": "AU-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    not has_falco_annotation
    not has_audit_sidecar
    msg := sprintf("%s '%s' has no audit logging — add 'falco.org/monitored: true' annotation or an audit sidecar container", [input.kind, input.metadata.name])
}

has_falco_annotation {
    lib.annotation_value(lib.pod_metadata, "falco.org/monitored") == "true"
}

has_audit_sidecar {
    container := lib.all_containers[_]
    contains(container.name, "audit")
}

has_audit_sidecar {
    container := lib.all_containers[_]
    contains(container.name, "fluentbit")
}

has_audit_sidecar {
    container := lib.all_containers[_]
    contains(container.name, "fluentd")
}

has_audit_sidecar {
    container := lib.all_containers[_]
    contains(container.name, "vector")
}

# MEDIUM: Require audit volume mounts for log collection
# THREAT: Logs not written to persistent volume are lost on pod restart
# COMPLIANCE: NIST AU-3 — content of audit records
violation[{"msg": msg, "severity": "MEDIUM", "control": "AU-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    has_audit_sidecar
    not has_audit_volume
    msg := sprintf("%s '%s' has audit sidecar but no log volume mount — add a volume for /var/log/audit", [input.kind, input.metadata.name])
}

has_audit_volume {
    volume := lib.pod_spec.volumes[_]
    contains(volume.name, "audit")
}

has_audit_volume {
    volume := lib.pod_spec.volumes[_]
    contains(volume.name, "log")
}

# MEDIUM: Require log-format label for parsing
# THREAT: Unstructured logs cannot be automatically analyzed
# COMPLIANCE: NIST AU-3 — audit record content includes event type and outcome
violation[{"msg": msg, "severity": "MEDIUM", "control": "AU-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    not lib.has_label(lib.pod_metadata, "novasec.cloud/log-format")
    msg := sprintf("%s '%s' missing label 'novasec.cloud/log-format' (json|cef|syslog) — required for log parsing", [input.kind, input.metadata.name])
}

# HIGH: Namespaces must have audit-level annotation
# THREAT: Namespace without audit policy may not capture security events
# COMPLIANCE: NIST AU-12 — audit generation
violation[{"msg": msg, "severity": "HIGH", "control": "AU-2"}] {
    lib.is_namespace
    not lib.is_system_namespace(input.metadata.name)
    not lib.has_annotation(input, "novasec.cloud/audit-level")
    msg := sprintf("Namespace '%s' missing annotation 'novasec.cloud/audit-level' (metadata|request|requestresponse)", [input.metadata.name])
}
