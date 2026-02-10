package novasec.ac2

# AC-2: Account Management
# Ensures workloads use explicit, tenant-scoped service accounts
# and do not auto-mount tokens unnecessarily.

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.novasec.lib

metadata := {
    "policy": "ac2-account-management",
    "version": "1.0.0",
    "compliance": ["NIST-AC-2", "NIST-AC-2(1)", "FedRAMP-MOD"],
    "risk_level": "HIGH",
    "author": "GuidePoint Security Engineering",
    "last_review": "2026-02-10",
}

# HIGH: Block default service account usage
# THREAT: Shared default SA credentials enable lateral movement across pods
# COMPLIANCE: NIST AC-2 — accounts must be individually assigned
violation[{"msg": msg, "severity": "HIGH", "control": "AC-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    sa := lib.pod_spec.serviceAccountName
    sa == "default"
    msg := sprintf("%s '%s' uses the default ServiceAccount — assign a dedicated SA", [input.kind, input.metadata.name])
}

violation[{"msg": msg, "severity": "HIGH", "control": "AC-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    not lib.pod_spec.serviceAccountName
    msg := sprintf("%s '%s' has no serviceAccountName — defaults to 'default' SA", [input.kind, input.metadata.name])
}

# MEDIUM: Require automountServiceAccountToken: false unless explicitly needed
# THREAT: Auto-mounted tokens let compromised pods call the K8s API
# COMPLIANCE: NIST AC-2(1) — automated account management
violation[{"msg": msg, "severity": "MEDIUM", "control": "AC-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    lib.pod_spec.automountServiceAccountToken == true
    not has_api_access_annotation
    msg := sprintf("%s '%s' auto-mounts SA token — set automountServiceAccountToken: false or add 'novasec.cloud/api-access: required' annotation", [input.kind, input.metadata.name])
}

has_api_access_annotation {
    lib.annotation_value(input, "novasec.cloud/api-access") == "required"
}

has_api_access_annotation {
    lib.is_workload
    not lib.is_pod
    lib.annotation_value(input.spec.template, "novasec.cloud/api-access") == "required"
}

# MEDIUM: Service account naming convention — must include tenant prefix
# THREAT: Ungoverned SA names prevent auditing account ownership
# COMPLIANCE: NIST AC-2 — account naming conventions
violation[{"msg": msg, "severity": "MEDIUM", "control": "AC-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    sa := lib.pod_spec.serviceAccountName
    sa != "default"
    not contains(sa, "-")
    msg := sprintf("%s '%s' SA name '%s' does not follow naming convention <tenant>-<service>-sa", [input.kind, input.metadata.name, sa])
}

# HIGH: Pods must declare a tenant label for account scoping
# THREAT: Unscoped workloads bypass tenant isolation controls
# COMPLIANCE: NIST AC-2 — account assignment by organizational unit
violation[{"msg": msg, "severity": "HIGH", "control": "AC-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    not lib.has_label(lib.pod_metadata, "novasec.cloud/tenant")
    msg := sprintf("%s '%s' missing label 'novasec.cloud/tenant' — required for account scoping", [input.kind, input.metadata.name])
}
