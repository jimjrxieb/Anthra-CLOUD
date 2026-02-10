package novasec.sc7

# SC-7: Boundary Protection
# Enforces network segmentation via NetworkPolicy requirements,
# default-deny posture, and tenant namespace isolation.

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.novasec.lib

metadata := {
    "policy": "sc7-boundary-protection",
    "version": "1.0.0",
    "compliance": ["NIST-SC-7", "NIST-SC-7(5)", "NIST-SC-7(18)", "CIS-5.3.2", "FedRAMP-MOD"],
    "risk_level": "CRITICAL",
    "author": "GuidePoint Security Engineering",
    "last_review": "2026-02-10",
}

# CRITICAL: Namespaces must have a NetworkPolicy annotation confirming default-deny
# THREAT: Without default-deny, any pod can reach any other pod — lateral movement
# COMPLIANCE: NIST SC-7 — deny by default
violation[{"msg": msg, "severity": "CRITICAL", "control": "SC-7"}] {
    lib.is_namespace
    not lib.is_system_namespace(input.metadata.name)
    not lib.has_annotation(input, "novasec.cloud/network-policy")
    msg := sprintf("Namespace '%s' missing annotation 'novasec.cloud/network-policy: default-deny' — NetworkPolicy required", [input.metadata.name])
}

violation[{"msg": msg, "severity": "CRITICAL", "control": "SC-7"}] {
    lib.is_namespace
    not lib.is_system_namespace(input.metadata.name)
    policy := lib.annotation_value(input, "novasec.cloud/network-policy")
    policy != "default-deny"
    msg := sprintf("Namespace '%s' has network-policy '%s' — must be 'default-deny'", [input.metadata.name, policy])
}

# HIGH: Block NodePort services
# THREAT: NodePort exposes workloads on every node's IP — bypasses ingress controls
# COMPLIANCE: NIST SC-7(5) — deny by default, allow by exception
violation[{"msg": msg, "severity": "HIGH", "control": "SC-7"}] {
    lib.is_service
    input.spec.type == "NodePort"
    msg := sprintf("Service '%s' uses NodePort — use ClusterIP + Ingress for controlled boundary access", [input.metadata.name])
}

# HIGH: Block LoadBalancer services (use Ingress instead)
# THREAT: Direct LoadBalancer bypasses WAF, rate limiting, TLS termination at ingress
# COMPLIANCE: NIST SC-7(18) — fail-secure
violation[{"msg": msg, "severity": "HIGH", "control": "SC-7"}] {
    lib.is_service
    input.spec.type == "LoadBalancer"
    not lib.is_system_namespace(input.metadata.namespace)
    msg := sprintf("Service '%s' uses LoadBalancer — use ClusterIP + Ingress for centralized boundary protection", [input.metadata.name])
}

# MEDIUM: Namespaces must have tenant isolation label
# THREAT: Unlabeled namespaces cannot be targeted by NetworkPolicy selectors
# COMPLIANCE: NIST SC-7 — boundary protection between tenants
violation[{"msg": msg, "severity": "MEDIUM", "control": "SC-7"}] {
    lib.is_namespace
    not lib.is_system_namespace(input.metadata.name)
    not lib.has_label(input, "novasec.cloud/tenant")
    msg := sprintf("Namespace '%s' missing label 'novasec.cloud/tenant' — required for NetworkPolicy tenant isolation", [input.metadata.name])
}

# HIGH: NetworkPolicy must not allow all ingress (empty ingress = allow-all)
# THREAT: Open ingress defeats default-deny posture
# COMPLIANCE: NIST SC-7 — managed interfaces
violation[{"msg": msg, "severity": "HIGH", "control": "SC-7"}] {
    lib.is_networkpolicy
    not input.spec.ingress
    count(input.spec.policyTypes) > 0
    "Ingress" in input.spec.policyTypes
    msg := sprintf("NetworkPolicy '%s' has empty ingress rules — acts as default-deny (OK) or missing rules (review)", [input.metadata.name])
}

# MEDIUM: Workloads should not use hostPort
# THREAT: hostPort binds to node interface, bypasses NetworkPolicy
# COMPLIANCE: NIST SC-7(5)
violation[{"msg": msg, "severity": "MEDIUM", "control": "SC-7"}] {
    lib.is_workload
    container := lib.all_containers[_]
    port := container.ports[_]
    port.hostPort
    msg := sprintf("Container '%s' in %s '%s' uses hostPort %d — bypasses NetworkPolicy", [container.name, input.kind, input.metadata.name, port.hostPort])
}
