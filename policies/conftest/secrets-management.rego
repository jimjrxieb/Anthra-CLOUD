package kubernetes.admission.security.secrets

# UNDERSTANDING: Secrets in environment variables = plaintext in process listings
# Volume-mounted secrets = files in memory, less exposure surface
# External secrets managers = best practice, but enforce fallback security
#
# INPUT: Raw Kubernetes YAML (conftest format — input IS the resource)

import future.keywords.contains
import future.keywords.if
import future.keywords.in

metadata := {
    "policy": "secrets-management-enforcement",
    "version": "1.1.0",
    "compliance": ["CIS-5.4.1", "SOC2-CC6.1", "NIST-SC-28", "PCI-DSS-3.4"],
    "principle": "defense-in-depth-secrets",
    "last_review": "2026-02-26"
}

# --- Kind guards: only evaluate on resources that have containers/pods ---
workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job"}

is_workload {
    workload_kinds[input.kind]
}

is_pod {
    input.kind == "Pod"
}

is_cronjob {
    input.kind == "CronJob"
}

# --- Container extraction helpers ---
# Deployment, StatefulSet, DaemonSet, Job
containers[container] {
    is_workload
    container := input.spec.template.spec.containers[_]
}

# Pod
containers[container] {
    is_pod
    container := input.spec.containers[_]
}

# CronJob
containers[container] {
    is_cronjob
    container := input.spec.jobTemplate.spec.template.spec.containers[_]
}

# Volume extraction helpers
volumes[volume] {
    is_workload
    volume := input.spec.template.spec.volumes[_]
}

volumes[volume] {
    is_pod
    volume := input.spec.volumes[_]
}

volumes[volume] {
    is_cronjob
    volume := input.spec.jobTemplate.spec.template.spec.volumes[_]
}

# Pod spec extraction
pod_spec := input.spec.template.spec {
    is_workload
}

pod_spec := input.spec {
    is_pod
}

pod_spec := input.spec.jobTemplate.spec.template.spec {
    is_cronjob
}

# CRITICAL: Secrets in environment variables
# THREAT: Process listing exposure, log leakage, crash dumps
# COMPLIANCE: CIS 5.4.1, PCI-DSS 3.4
deny[msg] {
    container := containers[_]
    env := container.env[_]
    env.valueFrom.secretKeyRef
    msg := sprintf("Container '%v' uses secret '%v' as environment variable - use volume mount",
                   [container.name, env.valueFrom.secretKeyRef.name])
}

# HIGH: Hardcoded secrets detection
# THREAT: Credential exposure in version control, image layers
# COMPLIANCE: SOC2 CC6.1, NIST IA-5
deny[msg] {
    container := containers[_]
    env := container.env[_]
    env.value
    is_hardcoded_secret(env.name, env.value)
    msg := sprintf("Container '%v' has hardcoded secret in env '%v'", [container.name, env.name])
}

is_hardcoded_secret(name, value) {
    lower(name) in ["password", "api_key", "secret", "token", "access_key"]
    not value == ""
}

is_hardcoded_secret(name, value) {
    # Pattern matching for common secret formats
    regex.match(`^[A-Za-z0-9+/]{40,}={0,2}$`, value)  # Base64-like
}

is_hardcoded_secret(name, value) {
    regex.match(`^[A-Z0-9]{20,}$`, value)  # AWS access key pattern
}

# HIGH: Secret volume permissions
# THREAT: World-readable secrets, privilege escalation
# COMPLIANCE: CIS 5.4.2
deny[msg] {
    volume := volumes[_]
    volume.secret
    not volume.secret.defaultMode == 256  # 0400 octal
    msg := sprintf("Secret volume '%v' must have mode 0400 (read-only owner)", [volume.name])
}

# MEDIUM: Enforce external secrets operator (production only)
# THREAT: Secrets stored in etcd, backup exposure
# COMPLIANCE: SOC2 CC6.1
warn[msg] {
    is_workload
    is_production
    volume := volumes[_]
    volume.secret
    not has_external_secrets_annotation
    msg := "Production pods should use external secrets manager (AWS Secrets Manager, Vault)"
}

has_external_secrets_annotation {
    input.metadata.annotations["external-secrets.io/backend"]
}

is_production {
    input.metadata.namespace in ["production", "prod"]
}

# HIGH: Service account token auto-mount
# THREAT: Unnecessary API access, token theft
# COMPLIANCE: CIS 5.1.5
deny[msg] {
    pod_spec
    not pod_spec.automountServiceAccountToken == false
    not needs_api_access
    msg := sprintf("%v '%v' should set automountServiceAccountToken: false unless API access required",
                   [input.kind, input.metadata.name])
}

needs_api_access {
    # Allow if explicitly annotated
    input.metadata.annotations["security.ghostprotocol.io/needs-api-access"] == "true"
}

# MEDIUM: Secret rotation metadata
# THREAT: Stale credentials, extended exposure window
# COMPLIANCE: NIST IA-5(1), PCI-DSS 8.2.4
warn[msg] {
    input.kind == "Secret"
    input.type in ["Opaque", "kubernetes.io/basic-auth", "kubernetes.io/tls"]
    not input.metadata.annotations["secret.ghostprotocol.io/rotation-date"]
    msg := sprintf("Secret '%v' missing rotation date annotation", [input.metadata.name])
}
