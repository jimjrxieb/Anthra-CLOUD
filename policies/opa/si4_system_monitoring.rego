package novasec.si4

# SI-4: Information System Monitoring
# Ensures Falco daemonset is deployed, Prometheus scraping is configured,
# log-collection sidecars are present, and monitoring namespace exists.

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.novasec.lib

metadata := {
    "policy": "si4-system-monitoring",
    "version": "1.0.0",
    "compliance": ["NIST-SI-4", "NIST-SI-4(2)", "NIST-SI-4(5)", "FedRAMP-MOD"],
    "risk_level": "HIGH",
    "author": "GuidePoint Security Engineering",
    "last_review": "2026-02-10",
}

# HIGH: Falco DaemonSet required for runtime monitoring
# THREAT: Without runtime detection, container escapes and crypto miners go unnoticed
# COMPLIANCE: NIST SI-4 — system monitoring
violation[{"msg": msg, "severity": "HIGH", "control": "SI-4"}] {
    lib.is_daemonset
    input.metadata.namespace == "falco"
    not contains(input.metadata.name, "falco")
    msg := sprintf("DaemonSet '%s' in falco namespace does not match expected Falco naming — verify Falco deployment", [input.metadata.name])
}

# HIGH: Workloads should have Prometheus scrape annotations
# THREAT: Unmonitored services cannot generate alerts for anomalous behavior
# COMPLIANCE: NIST SI-4(2) — automated tools for real-time analysis
violation[{"msg": msg, "severity": "MEDIUM", "control": "SI-4"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    not has_prometheus_annotations
    msg := sprintf("%s '%s' missing Prometheus scrape annotations — add prometheus.io/scrape: 'true'", [input.kind, input.metadata.name])
}

has_prometheus_annotations {
    lib.annotation_value(lib.pod_metadata, "prometheus.io/scrape") == "true"
}

# MEDIUM: Workloads should have a log-collection sidecar or log shipping annotation
# THREAT: Logs stored only in container stdout are lost on crash or eviction
# COMPLIANCE: NIST SI-4(5) — alert on detection of unauthorized activities
violation[{"msg": msg, "severity": "MEDIUM", "control": "SI-4"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    not has_log_collection
    msg := sprintf("%s '%s' has no log collection — add a fluentbit/vector sidecar or 'novasec.cloud/log-shipping: enabled' annotation", [input.kind, input.metadata.name])
}

has_log_collection {
    container := lib.all_containers[_]
    container.name in {"fluentbit", "fluent-bit", "fluentd", "vector", "filebeat", "log-collector"}
}

has_log_collection {
    lib.annotation_value(lib.pod_metadata, "novasec.cloud/log-shipping") == "enabled"
}

# HIGH: Monitoring namespace must exist and have required labels
# THREAT: No centralized monitoring namespace means ad-hoc, ungoverned monitoring
# COMPLIANCE: NIST SI-4 — centralized monitoring infrastructure
violation[{"msg": msg, "severity": "HIGH", "control": "SI-4"}] {
    lib.is_namespace
    input.metadata.name == "monitoring"
    not lib.has_label(input, "novasec.cloud/monitoring-stack")
    msg := "Namespace 'monitoring' missing label 'novasec.cloud/monitoring-stack' — required to confirm monitoring infrastructure"
}

# MEDIUM: Workloads must declare liveness and readiness probes
# THREAT: Without probes, failing services remain in rotation — silent degradation
# COMPLIANCE: NIST SI-4 — ongoing monitoring of service health
violation[{"msg": msg, "severity": "MEDIUM", "control": "SI-4"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    container := lib.pod_spec.containers[_]
    not container.livenessProbe
    msg := sprintf("Container '%s' in %s '%s' missing livenessProbe — required for health monitoring", [container.name, input.kind, input.metadata.name])
}

violation[{"msg": msg, "severity": "MEDIUM", "control": "SI-4"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    container := lib.pod_spec.containers[_]
    not container.readinessProbe
    msg := sprintf("Container '%s' in %s '%s' missing readinessProbe — required for traffic management", [container.name, input.kind, input.metadata.name])
}
