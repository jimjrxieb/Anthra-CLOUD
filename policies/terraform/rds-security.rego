# RDS Security Controls — Terraform Plan Validation
# NIST 800-53: SC-28, SC-8, CP-9, AC-3
#
# Usage: conftest test tfplan.json --policy policies/terraform/

package main

import future.keywords.in

# --- SC-28: RDS must have encryption at rest ---
deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_db_instance"
  planned := r.change.after
  not planned.storage_encrypted
  msg := sprintf("RDS instance '%v' must have storage encryption enabled (NIST SC-28).", [r.name])
}

deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_db_instance"
  planned := r.change.after
  planned.storage_encrypted == false
  msg := sprintf("RDS instance '%v' has storage encryption disabled (NIST SC-28).", [r.name])
}

# --- CP-9: RDS must have backups enabled (FedRAMP: 35+ days) ---
deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_db_instance"
  planned := r.change.after
  planned.backup_retention_period < 7
  msg := sprintf("RDS instance '%v' backup retention is %v days. Minimum 7 days required, 35 for FedRAMP (NIST CP-9).", [r.name, planned.backup_retention_period])
}

warn[msg] {
  r := input.resource_changes[_]
  r.type == "aws_db_instance"
  planned := r.change.after
  planned.backup_retention_period < 35
  planned.backup_retention_period >= 7
  msg := sprintf("RDS instance '%v' backup retention is %v days. FedRAMP Moderate recommends 35 days (NIST CP-9).", [r.name, planned.backup_retention_period])
}

# --- AC-3: RDS must not be publicly accessible ---
deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_db_instance"
  planned := r.change.after
  planned.publicly_accessible == true
  msg := sprintf("RDS instance '%v' is publicly accessible. Must be private (NIST AC-3).", [r.name])
}

# --- SC-28: RDS should have deletion protection in production ---
warn[msg] {
  r := input.resource_changes[_]
  r.type == "aws_db_instance"
  planned := r.change.after
  not planned.deletion_protection
  msg := sprintf("RDS instance '%v' does not have deletion protection enabled.", [r.name])
}

# --- SC-8: Multi-AZ for production availability ---
warn[msg] {
  r := input.resource_changes[_]
  r.type == "aws_db_instance"
  planned := r.change.after
  planned.multi_az == false
  msg := sprintf("RDS instance '%v' is not Multi-AZ. Recommended for production availability.", [r.name])
}
