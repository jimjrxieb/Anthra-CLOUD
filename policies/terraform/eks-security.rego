# EKS Security Controls — Terraform Plan Validation
# NIST 800-53: SC-7, SC-8, SC-28, AC-6, AU-2
#
# Usage: conftest test tfplan.json --policy policies/terraform/

package main

import future.keywords.in

# Helper: get planned resource changes by type
resources_by_type(type) = resources {
  resources := [r | r := input.resource_changes[_]; r.type == type]
}

# --- SC-28: EKS secrets must use KMS envelope encryption ---
deny[msg] {
  r := resources_by_type("aws_eks_cluster")[_]
  planned := r.change.after
  not planned.encryption_config
  msg := sprintf("EKS cluster '%v' must have KMS envelope encryption for secrets (NIST SC-28).", [r.name])
}

# --- SC-7: EKS should not have public endpoint in production ---
warn[msg] {
  r := resources_by_type("aws_eks_cluster")[_]
  planned := r.change.after
  vpc_config := planned.vpc_config[_]
  vpc_config.endpoint_public_access == true
  msg := sprintf("EKS cluster '%v' has public API endpoint enabled. Disable for production (NIST SC-7).", [r.name])
}

# --- AU-2: EKS control plane logging must be enabled ---
warn[msg] {
  r := resources_by_type("aws_eks_cluster")[_]
  planned := r.change.after
  not planned.enabled_cluster_log_types
  msg := sprintf("EKS cluster '%v' should have control plane logging enabled (NIST AU-2).", [r.name])
}

# --- AC-6: Node groups should not use overly large instances ---
warn[msg] {
  r := resources_by_type("aws_eks_node_group")[_]
  planned := r.change.after
  instance_type := planned.instance_types[_]
  oversized := {"m5.4xlarge", "m5.8xlarge", "m5.12xlarge", "m5.24xlarge", "c5.9xlarge", "c5.18xlarge", "r5.8xlarge", "r5.12xlarge"}
  instance_type in oversized
  msg := sprintf("Node group '%v' uses oversized instance type '%v'. Verify this is intentional.", [r.name, instance_type])
}
