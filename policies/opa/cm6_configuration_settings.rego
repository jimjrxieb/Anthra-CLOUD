package novasec.cm6

# CM-6: Configuration Settings
# Enforces resource limits, required labels, pinned image tags,
# and approved container registries.

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.novasec.lib

metadata := {
    "policy": "cm6-configuration-settings",
    "version": "1.0.0",
    "compliance": ["NIST-CM-6", "NIST-CM-6(1)", "NIST-CM-2", "CIS-5.7.3", "FedRAMP-MOD"],
    "risk_level": "HIGH",
    "author": "GuidePoint Security Engineering",
    "last_review": "2026-02-10",
}

# Required labels for all workloads
required_labels := {"app", "version", "novasec.cloud/tenant", "novasec.cloud/owner"}

# HIGH: Require resource limits (memory)
# THREAT: Unbounded memory leads to OOMKill cascades, denial of service
# COMPLIANCE: NIST CM-6, CIS 5.7.3
violation[{"msg": msg, "severity": "HIGH", "control": "CM-6"}] {
    lib.is_workload
    container := lib.all_containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%s' in %s '%s' missing memory limits — required to prevent resource exhaustion", [container.name, input.kind, input.metadata.name])
}

# HIGH: Require resource limits (CPU)
# THREAT: CPU-intensive workloads starve neighbors in multi-tenant cluster
# COMPLIANCE: NIST CM-6, CIS 5.7.3
violation[{"msg": msg, "severity": "HIGH", "control": "CM-6"}] {
    lib.is_workload
    container := lib.all_containers[_]
    not container.resources.limits.cpu
    msg := sprintf("Container '%s' in %s '%s' missing CPU limits — required for multi-tenant fairness", [container.name, input.kind, input.metadata.name])
}

# HIGH: Require resource requests
# THREAT: Scheduler cannot bin-pack properly without requests, causes eviction
# COMPLIANCE: NIST CM-6
violation[{"msg": msg, "severity": "MEDIUM", "control": "CM-6"}] {
    lib.is_workload
    container := lib.all_containers[_]
    not container.resources.requests.memory
    msg := sprintf("Container '%s' in %s '%s' missing memory requests", [container.name, input.kind, input.metadata.name])
}

# MEDIUM: Require standard labels
# THREAT: Unlabeled workloads cannot be tracked, audited, or isolated by tenant
# COMPLIANCE: NIST CM-2 — baseline configuration
violation[{"msg": msg, "severity": "MEDIUM", "control": "CM-6"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    some label in required_labels
    not lib.has_label(lib.pod_metadata, label)
    msg := sprintf("%s '%s' missing required label '%s'", [input.kind, input.metadata.name, label])
}

# HIGH: Block :latest and mutable tags
# THREAT: Mutable tags allow supply chain injection — image content changes after review
# COMPLIANCE: NIST CM-6(1) — automated configuration management
violation[{"msg": msg, "severity": "HIGH", "control": "CM-6"}] {
    lib.is_workload
    container := lib.all_containers[_]
    lib.image_has_mutable_tag(container.image)
    msg := sprintf("Container '%s' in %s '%s' uses mutable tag '%s' — pin to immutable digest or semver", [container.name, input.kind, input.metadata.name, container.image])
}

# HIGH: Require approved container registry
# THREAT: Untrusted registries may serve compromised images
# COMPLIANCE: NIST CM-6 — approved software list
violation[{"msg": msg, "severity": "HIGH", "control": "CM-6"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    container := lib.all_containers[_]
    not lib.is_approved_registry(container.image)
    msg := sprintf("Container '%s' in %s '%s' uses unapproved registry: '%s' — allowed: ghcr.io/novasec/, registry.novasec.cloud/", [container.name, input.kind, input.metadata.name, container.image])
}
