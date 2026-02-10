package novasec.sc8

# SC-8: Transmission Confidentiality
# Enforces TLS on all ingress, mTLS between services,
# and blocks plaintext service ports.

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.novasec.lib

metadata := {
    "policy": "sc8-transmission-confidentiality",
    "version": "1.0.0",
    "compliance": ["NIST-SC-8", "NIST-SC-8(1)", "NIST-SC-13", "FedRAMP-MOD"],
    "risk_level": "CRITICAL",
    "author": "GuidePoint Security Engineering",
    "last_review": "2026-02-10",
}

# Plaintext ports that must never be exposed
plaintext_ports := {80, 8080, 8000, 8888}

# CRITICAL: Ingress must have TLS configured
# THREAT: Plaintext ingress exposes credentials, PII, tenant data in transit
# COMPLIANCE: NIST SC-8 — confidentiality of transmitted information
violation[{"msg": msg, "severity": "CRITICAL", "control": "SC-8"}] {
    lib.is_ingress
    not input.spec.tls
    msg := sprintf("Ingress '%s' has no TLS configuration — all external traffic must be encrypted", [input.metadata.name])
}

violation[{"msg": msg, "severity": "CRITICAL", "control": "SC-8"}] {
    lib.is_ingress
    count(input.spec.tls) == 0
    msg := sprintf("Ingress '%s' has empty TLS config — provide at least one TLS entry with secretName", [input.metadata.name])
}

# HIGH: Ingress TLS must specify a secret (not rely on default cert)
# THREAT: Default TLS cert may not match domain, enabling MITM
# COMPLIANCE: NIST SC-8(1) — cryptographic protection
violation[{"msg": msg, "severity": "HIGH", "control": "SC-8"}] {
    lib.is_ingress
    tls_entry := input.spec.tls[_]
    not tls_entry.secretName
    msg := sprintf("Ingress '%s' TLS entry missing secretName — must reference a TLS Secret", [input.metadata.name])
}

# HIGH: Services must have mTLS annotation (Istio/Linkerd)
# THREAT: Internal service-to-service traffic without mTLS can be intercepted
# COMPLIANCE: NIST SC-8 — transmission confidentiality for internal comms
violation[{"msg": msg, "severity": "HIGH", "control": "SC-8"}] {
    lib.is_service
    not lib.is_system_namespace(input.metadata.namespace)
    not has_mtls_annotation
    msg := sprintf("Service '%s' missing mTLS annotation — add 'novasec.cloud/mtls: strict' or service mesh sidecar", [input.metadata.name])
}

has_mtls_annotation {
    lib.annotation_value(input, "novasec.cloud/mtls") == "strict"
}

has_mtls_annotation {
    lib.annotation_value(input, "security.istio.io/tlsMode") == "istio"
}

has_mtls_annotation {
    lib.has_annotation(input, "linkerd.io/inject")
}

# MEDIUM: Block plaintext ports on services
# THREAT: Ports 80, 8080 indicate unencrypted traffic
# COMPLIANCE: NIST SC-8 — prevent plaintext transmission
violation[{"msg": msg, "severity": "MEDIUM", "control": "SC-8"}] {
    lib.is_service
    not lib.is_system_namespace(input.metadata.namespace)
    port := input.spec.ports[_]
    port.port in plaintext_ports
    not has_mtls_annotation
    msg := sprintf("Service '%s' exposes plaintext port %d without mTLS — encrypt or use HTTPS port", [input.metadata.name, port.port])
}

# HIGH: Workloads must have service mesh sidecar for mTLS
# THREAT: Without mesh sidecar, pod-to-pod traffic is plaintext
# COMPLIANCE: NIST SC-8(1) — cryptographic protection
violation[{"msg": msg, "severity": "HIGH", "control": "SC-8"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    not has_mesh_sidecar
    not mesh_injection_enabled
    msg := sprintf("%s '%s' has no service mesh sidecar and injection is not enabled — required for mTLS", [input.kind, input.metadata.name])
}

has_mesh_sidecar {
    container := lib.all_containers[_]
    container.name == "istio-proxy"
}

has_mesh_sidecar {
    container := lib.all_containers[_]
    container.name == "linkerd-proxy"
}

mesh_injection_enabled {
    lib.annotation_value(lib.pod_metadata, "sidecar.istio.io/inject") == "true"
}

mesh_injection_enabled {
    lib.annotation_value(lib.pod_metadata, "linkerd.io/inject") == "enabled"
}
