package kubernetes.admission.security.images

# UNDERSTANDING: Container images are the attack surface entry point
# Untrusted registries = supply chain attacks (SolarWinds pattern)
# Unsigned images = tampering, backdoors
# Outdated images = known CVEs
#
# INPUT: Raw Kubernetes YAML (conftest format — input IS the resource)

import future.keywords.contains
import future.keywords.if
import future.keywords.in

metadata := {
    "policy": "container-image-security",
    "version": "1.1.0",
    "compliance": ["CIS-5.1.1", "NIST-SA-10", "SLSA-Level-3"],
    "supply_chain": "software-supply-chain-security",
    "last_review": "2026-02-26"
}

# --- Kind guards: only evaluate on resources that have containers ---
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
containers[container] {
    is_workload
    container := input.spec.template.spec.containers[_]
}

containers[container] {
    is_pod
    container := input.spec.containers[_]
}

containers[container] {
    is_cronjob
    container := input.spec.jobTemplate.spec.template.spec.containers[_]
}

# Init containers too
containers[container] {
    is_workload
    container := input.spec.template.spec.initContainers[_]
}

containers[container] {
    is_pod
    container := input.spec.initContainers[_]
}

# CRITICAL: Trusted registry enforcement
# THREAT: Supply chain attacks, malicious images
# COMPLIANCE: CIS 5.1.1, SLSA Level 3
deny[msg] {
    container := containers[_]
    not is_trusted_registry(container.image)
    msg := sprintf("Container '%v' uses untrusted registry: %v - use approved registries only",
                   [container.name, container.image])
}

trusted_registries := [
    "gcr.io/company",
    "company.azurecr.io",
    "123456789.dkr.ecr.us-east-1.amazonaws.com",
    "registry.company.com",
    "quay.io/company",
    "ghcr.io/jimjrxieb",
    "anthra",
    "postgres",
    "docker.io/library/postgres"
]

is_trusted_registry(image) {
    startswith(image, trusted_registries[_])
}

# CRITICAL: Latest tag prohibition
# THREAT: Unpredictable deployments, rollback issues
# COMPLIANCE: CIS 5.1.2, NIST CM-2
deny[msg] {
    container := containers[_]
    image_uses_latest_tag(container.image)
    msg := sprintf("Container '%v' uses ':latest' tag - use immutable tags (SHA256 digest preferred)",
                   [container.name])
}

image_uses_latest_tag(image) {
    endswith(image, ":latest")
}

image_uses_latest_tag(image) {
    not contains(image, ":")
    not contains(image, "@")
}

# HIGH: Image signature verification (production only)
# THREAT: Tampered images, man-in-the-middle attacks
# COMPLIANCE: SLSA Level 3, NIST SA-10
deny[msg] {
    container := containers[_]
    is_production
    not has_image_signature(container.image)
    msg := sprintf("Production container '%v' requires signed image with Cosign/Notary",
                   [container.name])
}

has_image_signature(image) {
    input.metadata.annotations["images.ghostprotocol.io/signature-verified"] == "true"
}

has_image_signature(image) {
    contains(image, "@sha256:")
}

# HIGH: Base image restrictions
# THREAT: Vulnerable base images, unnecessary attack surface
# COMPLIANCE: CIS 4.1, NIST SI-2
warn[msg] {
    container := containers[_]
    uses_prohibited_base_image(container.image)
    msg := sprintf("Container '%v' uses prohibited base image - use approved distroless/minimal images",
                   [container.name])
}

prohibited_base_patterns := [
    "ubuntu:latest",
    "debian:latest",
    "centos:latest"
]

uses_prohibited_base_image(image) {
    image == prohibited_base_patterns[_]
}

# MEDIUM: Image pull policy enforcement
# THREAT: Stale local images, missing security updates
# COMPLIANCE: CIS 5.1.3
warn[msg] {
    container := containers[_]
    container.imagePullPolicy
    not container.imagePullPolicy == "Always"
    not container.imagePullPolicy == "IfNotPresent"
    msg := sprintf("Container '%v' must set imagePullPolicy to 'Always' or 'IfNotPresent'",
                   [container.name])
}

# MEDIUM: Image scanning requirements (production only)
# THREAT: Known CVEs, vulnerable dependencies
# COMPLIANCE: NIST RA-5, PCI-DSS 6.2
warn[msg] {
    containers[_]
    is_production
    not has_scan_annotation
    msg := sprintf("%v '%v' in production requires image vulnerability scan attestation",
                   [input.kind, input.metadata.name])
}

has_scan_annotation {
    input.metadata.annotations["images.ghostprotocol.io/scan-date"]
    input.metadata.annotations["images.ghostprotocol.io/scan-status"] == "passed"
}

# LOW: Distroless/minimal image recommendation
# THREAT: Unnecessary tools enable privilege escalation
# COMPLIANCE: CIS 4.2, NIST CM-7
warn[msg] {
    container := containers[_]
    not is_minimal_image(container.image)
    not is_exempted
    msg := sprintf("Container '%v' should use distroless/minimal base image for reduced attack surface",
                   [container.name])
}

is_minimal_image(image) {
    contains(image, "distroless")
}

is_minimal_image(image) {
    contains(image, "scratch")
}

is_minimal_image(image) {
    regex.match(`.*alpine:\d+\.\d+`, image)  # Versioned alpine
}

is_production {
    input.metadata.namespace in ["production", "prod", "live"]
}

is_exempted {
    input.metadata.annotations["security.ghostprotocol.io/image-exemption"] == "true"
}
