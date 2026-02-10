package novasec.lib

# Shared helper functions for NovaSec Cloud FedRAMP Moderate OPA policies.
# Used by all 8 control policies via: import data.novasec.lib

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Resource type checks
is_pod {
    input.kind == "Pod"
}

is_deployment {
    input.kind == "Deployment"
}

is_statefulset {
    input.kind == "StatefulSet"
}

is_daemonset {
    input.kind == "DaemonSet"
}

is_service {
    input.kind == "Service"
}

is_ingress {
    input.kind == "Ingress"
}

is_namespace {
    input.kind == "Namespace"
}

is_networkpolicy {
    input.kind == "NetworkPolicy"
}

# Workload check — any resource that contains a pod spec
is_workload {
    input.kind in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}
}

# Extract pod spec regardless of resource type
pod_spec := input.spec {
    is_pod
}

pod_spec := input.spec.template.spec {
    is_workload
    not is_pod
}

# Extract pod metadata regardless of resource type
pod_metadata := input.metadata {
    is_pod
}

pod_metadata := input.spec.template.metadata {
    is_workload
    not is_pod
}

# Get all containers (containers + initContainers + ephemeralContainers)
all_containers[container] {
    container := pod_spec.containers[_]
}

all_containers[container] {
    container := pod_spec.initContainers[_]
}

all_containers[container] {
    container := pod_spec.ephemeralContainers[_]
}

# Label and annotation helpers
has_label(obj, key) {
    obj.metadata.labels[key]
}

has_annotation(obj, key) {
    obj.metadata.annotations[key]
}

label_value(obj, key) := obj.metadata.labels[key]

annotation_value(obj, key) := obj.metadata.annotations[key]

# Approved container registries for NovaSec Cloud
approved_registries := [
    "ghcr.io/novasec/",
    "registry.novasec.cloud/",
]

is_approved_registry(image) {
    some prefix in approved_registries
    startswith(image, prefix)
}

# System namespaces exempt from tenant policies
system_namespaces := {"kube-system", "kube-public", "kube-node-lease", "gatekeeper-system", "falco", "monitoring", "istio-system"}

is_system_namespace(ns) {
    ns in system_namespaces
}

# Tag checks
image_has_latest_tag(image) {
    endswith(image, ":latest")
}

image_has_latest_tag(image) {
    not contains(image, ":")
}

image_has_mutable_tag(image) {
    tag := split(image, ":")[1]
    tag in {"latest", "dev", "staging", "nightly", "edge"}
}
