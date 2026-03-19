# NIST 800-53 CM-2: BASELINE CONFIGURATION
# Purpose: Ensure all containers have defined resource limits.
# FedRAMP requires that all systems be configured to prevent resource 
# exhaustion and ensure availability.
#
# Usage: conftest test infrastructure/*.yaml --policy GP-Copilot/opa-package/

package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.cpu
  msg := sprintf("Container '%v' in Deployment '%v' must have CPU limits defined (NIST CM-2).", [container.name, input.metadata.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container '%v' in Deployment '%v' must have memory limits defined (NIST CM-2).", [container.name, input.metadata.name])
}

warn[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.cpu
  msg := sprintf("Container '%v' in Deployment '%v' should have CPU requests defined for better scheduling.", [container.name, input.metadata.name])
}
