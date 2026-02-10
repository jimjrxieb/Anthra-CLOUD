package novasec.ac6

# AC-6: Least Privilege
# Enforces minimal container capabilities, non-root execution,
# and blocks host namespace access.

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.novasec.lib

metadata := {
    "policy": "ac6-least-privilege",
    "version": "1.0.0",
    "compliance": ["NIST-AC-6", "NIST-AC-6(9)", "NIST-AC-6(10)", "CIS-5.2", "FedRAMP-MOD"],
    "risk_level": "CRITICAL",
    "author": "GuidePoint Security Engineering",
    "last_review": "2026-02-10",
}

# CRITICAL: Block privileged containers
# THREAT: CVE-2019-5736 — privileged containers can escape to host
# COMPLIANCE: NIST AC-6, CIS 5.2.5
violation[{"msg": msg, "severity": "CRITICAL", "control": "AC-6"}] {
    lib.is_workload
    container := lib.all_containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%s' in %s '%s' runs as privileged — enables host escape", [container.name, input.kind, input.metadata.name])
}

# CRITICAL: Require runAsNonRoot
# THREAT: Root in container can escalate to host root via kernel exploits
# COMPLIANCE: NIST AC-6(10), CIS 5.2.6
violation[{"msg": msg, "severity": "CRITICAL", "control": "AC-6"}] {
    lib.is_workload
    container := lib.all_containers[_]
    not container_runs_as_nonroot(container)
    msg := sprintf("Container '%s' in %s '%s' does not enforce runAsNonRoot: true", [container.name, input.kind, input.metadata.name])
}

container_runs_as_nonroot(container) {
    container.securityContext.runAsNonRoot == true
}

container_runs_as_nonroot(container) {
    lib.pod_spec.securityContext.runAsNonRoot == true
}

# HIGH: Require drop ALL capabilities
# THREAT: NET_ADMIN, SYS_ADMIN enable network sniffing, kernel manipulation
# COMPLIANCE: NIST AC-6(9), CIS 5.2.7
violation[{"msg": msg, "severity": "HIGH", "control": "AC-6"}] {
    lib.is_workload
    container := lib.all_containers[_]
    not drops_all_capabilities(container)
    msg := sprintf("Container '%s' in %s '%s' must drop ALL capabilities", [container.name, input.kind, input.metadata.name])
}

drops_all_capabilities(container) {
    "ALL" in container.securityContext.capabilities.drop
}

# HIGH: Require readOnlyRootFilesystem
# THREAT: Malware persistence, binary replacement attacks
# COMPLIANCE: NIST AC-6, CIS 5.2.11
violation[{"msg": msg, "severity": "HIGH", "control": "AC-6"}] {
    lib.is_workload
    container := lib.all_containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%s' in %s '%s' must set readOnlyRootFilesystem: true", [container.name, input.kind, input.metadata.name])
}

# HIGH: Block allowPrivilegeEscalation
# THREAT: Process can gain more privileges than parent via setuid/setgid
# COMPLIANCE: NIST AC-6, CIS 5.2.3
violation[{"msg": msg, "severity": "HIGH", "control": "AC-6"}] {
    lib.is_workload
    container := lib.all_containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("Container '%s' in %s '%s' allows privilege escalation — set to false", [container.name, input.kind, input.metadata.name])
}

# CRITICAL: Block host PID namespace
# THREAT: Host PID enables process manipulation, signal injection
# COMPLIANCE: NIST AC-6, CIS 5.2.2
violation[{"msg": msg, "severity": "CRITICAL", "control": "AC-6"}] {
    lib.is_workload
    lib.pod_spec.hostPID == true
    msg := sprintf("%s '%s' uses hostPID — enables host process manipulation", [input.kind, input.metadata.name])
}

# CRITICAL: Block host network namespace
# THREAT: Host network enables sniffing, spoofing, service impersonation
# COMPLIANCE: NIST AC-6, CIS 5.2.4
violation[{"msg": msg, "severity": "CRITICAL", "control": "AC-6"}] {
    lib.is_workload
    lib.pod_spec.hostNetwork == true
    msg := sprintf("%s '%s' uses hostNetwork — enables network sniffing and spoofing", [input.kind, input.metadata.name])
}

# CRITICAL: Block host IPC namespace
# THREAT: Host IPC enables shared memory access across containers
# COMPLIANCE: NIST AC-6, CIS 5.2.3
violation[{"msg": msg, "severity": "CRITICAL", "control": "AC-6"}] {
    lib.is_workload
    lib.pod_spec.hostIPC == true
    msg := sprintf("%s '%s' uses hostIPC — enables shared memory access to host", [input.kind, input.metadata.name])
}
