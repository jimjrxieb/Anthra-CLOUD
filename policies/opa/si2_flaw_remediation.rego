package novasec.si2

# SI-2: Flaw Remediation
# Ensures images are pinned to immutable tags, pulled from approved registries,
# and have been scanned by Trivy before deployment.

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.novasec.lib

metadata := {
    "policy": "si2-flaw-remediation",
    "version": "1.0.0",
    "compliance": ["NIST-SI-2", "NIST-SI-2(2)", "NIST-RA-5", "FedRAMP-MOD"],
    "risk_level": "HIGH",
    "author": "GuidePoint Security Engineering",
    "last_review": "2026-02-10",
}

# Mutable tags that indicate unvetted images
mutable_tags := {"latest", "dev", "staging", "nightly", "edge", "canary"}

# CRITICAL: Block mutable image tags
# THREAT: Mutable tags allow supply chain attacks — image content changes after review
# COMPLIANCE: NIST SI-2 — flaw remediation (know exactly what you deploy)
violation[{"msg": msg, "severity": "CRITICAL", "control": "SI-2"}] {
    lib.is_workload
    container := lib.all_containers[_]
    tag := image_tag(container.image)
    tag in mutable_tags
    msg := sprintf("Container '%s' in %s '%s' uses mutable tag '%s' — pin to semver or digest", [container.name, input.kind, input.metadata.name, tag])
}

# HIGH: Block images with no tag (defaults to :latest)
# THREAT: No tag = :latest = mutable = uncontrolled supply chain
# COMPLIANCE: NIST SI-2
violation[{"msg": msg, "severity": "HIGH", "control": "SI-2"}] {
    lib.is_workload
    container := lib.all_containers[_]
    not contains(container.image, ":")
    not contains(container.image, "@sha256:")
    msg := sprintf("Container '%s' in %s '%s' has no image tag — defaults to :latest", [container.name, input.kind, input.metadata.name])
}

# HIGH: Require approved registry
# THREAT: Public registries may serve compromised or backdoored images
# COMPLIANCE: NIST SI-2(2) — automated flaw remediation
violation[{"msg": msg, "severity": "HIGH", "control": "SI-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    container := lib.all_containers[_]
    not lib.is_approved_registry(container.image)
    msg := sprintf("Container '%s' image '%s' not from approved registry — allowed: ghcr.io/novasec/, registry.novasec.cloud/", [container.name, container.image])
}

# HIGH: Require trivy-scanned annotation
# THREAT: Unscanned images may contain known CVEs
# COMPLIANCE: NIST RA-5 — vulnerability scanning
violation[{"msg": msg, "severity": "HIGH", "control": "SI-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    not lib.has_annotation(lib.pod_metadata, "novasec.cloud/trivy-scanned")
    msg := sprintf("%s '%s' missing annotation 'novasec.cloud/trivy-scanned: <timestamp>' — image must be scanned before deploy", [input.kind, input.metadata.name])
}

# MEDIUM: Require scan recency (annotation value is ISO timestamp)
# THREAT: Stale scan results miss newly published CVEs
# COMPLIANCE: NIST SI-2 — timely flaw remediation
violation[{"msg": msg, "severity": "MEDIUM", "control": "SI-2"}] {
    lib.is_workload
    not lib.is_system_namespace(input.metadata.namespace)
    scan_date := lib.annotation_value(lib.pod_metadata, "novasec.cloud/trivy-scanned")
    scan_date == "unknown"
    msg := sprintf("%s '%s' has trivy-scanned annotation set to 'unknown' — provide ISO timestamp of last scan", [input.kind, input.metadata.name])
}

# Helper: Extract tag from image reference
image_tag(image) := tag {
    parts := split(image, ":")
    count(parts) == 2
    not contains(parts[1], "@")
    tag := parts[1]
}

image_tag(image) := "latest" {
    not contains(image, ":")
    not contains(image, "@sha256:")
}
