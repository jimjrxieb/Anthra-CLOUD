# Cost Guardrails — Terraform Plan Validation
# Catch expensive mistakes before they deploy.
#
# Usage: conftest test tfplan.json --policy policies/terraform/

package main

import future.keywords.in

# --- Warn on expensive instance types ---
expensive_instances := {
  "m5.4xlarge", "m5.8xlarge", "m5.12xlarge", "m5.24xlarge",
  "c5.4xlarge", "c5.9xlarge", "c5.18xlarge",
  "r5.4xlarge", "r5.8xlarge", "r5.12xlarge", "r5.24xlarge",
  "m6i.4xlarge", "m6i.8xlarge", "m6i.12xlarge",
  "p3.2xlarge", "p3.8xlarge", "p3.16xlarge",
  "g4dn.xlarge", "g4dn.2xlarge", "g4dn.4xlarge"
}

warn[msg] {
  r := input.resource_changes[_]
  r.type == "aws_instance"
  planned := r.change.after
  planned.instance_type in expensive_instances
  msg := sprintf("EC2 instance '%v' uses expensive type '%v'. Verify this is intentional.", [r.name, planned.instance_type])
}

# --- Warn on large RDS instances ---
expensive_rds := {
  "db.r5.large", "db.r5.xlarge", "db.r5.2xlarge", "db.r5.4xlarge",
  "db.r6g.large", "db.r6g.xlarge", "db.r6g.2xlarge",
  "db.m5.xlarge", "db.m5.2xlarge", "db.m5.4xlarge"
}

warn[msg] {
  r := input.resource_changes[_]
  r.type == "aws_db_instance"
  planned := r.change.after
  planned.instance_class in expensive_rds
  msg := sprintf("RDS instance '%v' uses '%v'. Consider if a smaller instance works for current load.", [r.name, planned.instance_class])
}

# --- Deny more than 10 nodes in a node group (prevent runaway scaling) ---
deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_eks_node_group"
  planned := r.change.after
  planned.scaling_config[_].max_size > 10
  msg := sprintf("Node group '%v' max_size is %v. Cap at 10 to prevent runaway cost. Increase intentionally.", [r.name, planned.scaling_config[_].max_size])
}

# --- Warn if no tags (unattributable cost) ---
# Terraform provider default_tags merge into tags_all, not tags.
# Check both fields to avoid false positives.
has_project_tag(planned) {
  planned.tags.Project
}
has_project_tag(planned) {
  planned.tags.project
}
has_project_tag(planned) {
  planned.tags_all.Project
}
has_project_tag(planned) {
  planned.tags_all.project
}

has_any_tags(planned) {
  planned.tags
}
has_any_tags(planned) {
  planned.tags_all
}

warn[msg] {
  r := input.resource_changes[_]
  r.type in {"aws_instance", "aws_db_instance", "aws_eks_cluster", "aws_s3_bucket"}
  planned := r.change.after
  not has_any_tags(planned)
  msg := sprintf("Resource '%v' (%v) has no tags. Cost attribution requires Project + Environment tags.", [r.name, r.type])
}

warn[msg] {
  r := input.resource_changes[_]
  r.type in {"aws_instance", "aws_db_instance", "aws_eks_cluster", "aws_s3_bucket"}
  planned := r.change.after
  has_any_tags(planned)
  not has_project_tag(planned)
  msg := sprintf("Resource '%v' (%v) is missing a Project tag for cost attribution.", [r.name, r.type])
}
