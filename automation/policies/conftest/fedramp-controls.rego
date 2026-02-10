# FedRAMP Controls — OPA/Conftest Policy
# Validates Kubernetes manifests against FedRAMP NIST 800-53 requirements
# Usage: conftest test automation/kubernetes/ --policy automation/policies/conftest/

package fedramp

import rego.v1

# AC-6: Containers must not run as root
deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.securityContext.runAsNonRoot
    msg := sprintf("AC-6: Container '%s' must set runAsNonRoot: true [Least Privilege]", [container.name])
}

# AC-6: Containers must not allow privilege escalation
deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("AC-6: Container '%s' must set allowPrivilegeEscalation: false [Least Privilege]", [container.name])
}

# AC-6: Containers must drop all capabilities
deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.securityContext.capabilities.drop
    msg := sprintf("AC-6: Container '%s' must drop ALL capabilities [Least Privilege]", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    caps := container.securityContext.capabilities.drop
    not "ALL" in caps
    msg := sprintf("AC-6: Container '%s' must drop ALL capabilities, currently drops: %v", [container.name, caps])
}

# CM-6: Containers must have resource limits
deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.resources.limits
    msg := sprintf("CM-6: Container '%s' must define resource limits [Configuration Settings]", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.resources.limits.memory
    msg := sprintf("CM-6: Container '%s' must define memory limits [Configuration Settings]", [container.name])
}

deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.resources.limits.cpu
    msg := sprintf("CM-6: Container '%s' must define CPU limits [Configuration Settings]", [container.name])
}

# SC-7: Namespace must have NetworkPolicy
deny contains msg if {
    input.kind == "Namespace"
    not input.metadata.labels["network-policy"]
    msg := sprintf("SC-7: Namespace '%s' should have network-policy label [Boundary Protection]", [input.metadata.name])
}

# CM-6: Deployments must not use host networking
deny contains msg if {
    input.kind == "Deployment"
    input.spec.template.spec.hostNetwork
    msg := "CM-6: Deployment must not use hostNetwork [Configuration Settings]"
}

# CM-6: Deployments must not use host PID
deny contains msg if {
    input.kind == "Deployment"
    input.spec.template.spec.hostPID
    msg := "CM-6: Deployment must not use hostPID [Configuration Settings]"
}

# AC-6: No privileged containers
deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    container.securityContext.privileged
    msg := sprintf("AC-6: Container '%s' must not be privileged [Least Privilege]", [container.name])
}

# CM-6: Read-only root filesystem
warn contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf("CM-6: Container '%s' should use readOnlyRootFilesystem [Configuration Settings]", [container.name])
}

# AU-2: RBAC should not use wildcard verbs
deny contains msg if {
    input.kind == "Role"
    some rule in input.rules
    "*" in rule.verbs
    msg := sprintf("AU-2: Role '%s' uses wildcard verbs — over-permissive [Audit Events]", [input.metadata.name])
}

deny contains msg if {
    input.kind == "ClusterRole"
    some rule in input.rules
    "*" in rule.verbs
    msg := sprintf("AU-2: ClusterRole '%s' uses wildcard verbs — over-permissive [Audit Events]", [input.metadata.name])
}

# AC-2: Service accounts should not automount tokens
warn contains msg if {
    input.kind == "Deployment"
    sa := input.spec.template.spec.automountServiceAccountToken
    sa != false
    msg := "AC-2: Consider setting automountServiceAccountToken: false [Account Management]"
}
