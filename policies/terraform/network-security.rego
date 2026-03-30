# Network Security Controls — Terraform Plan Validation
# NIST 800-53: SC-7, AC-4
#
# Usage: conftest test tfplan.json --policy policies/terraform/

package main

# --- SC-7: Security groups must not allow unrestricted ingress ---
deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_security_group_rule"
  planned := r.change.after
  planned.type == "ingress"
  planned.cidr_blocks[_] == "0.0.0.0/0"
  planned.from_port != 443
  msg := sprintf("Security group rule '%v' allows 0.0.0.0/0 ingress on port %v. Only port 443 (HTTPS) may be open to the internet (NIST SC-7).", [r.name, planned.from_port])
}

# --- SC-7: Security groups should not allow all egress ---
warn[msg] {
  r := input.resource_changes[_]
  r.type == "aws_security_group"
  planned := r.change.after
  egress := planned.egress[_]
  egress.cidr_blocks[_] == "0.0.0.0/0"
  egress.protocol == "-1"
  msg := sprintf("Security group '%v' allows unrestricted egress. Consider restricting to required destinations (NIST SC-7).", [r.name])
}

# --- SC-7: S3 buckets must block public access ---
deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket_public_access_block"
  planned := r.change.after
  planned.block_public_acls == false
  msg := sprintf("S3 bucket public access block '%v' does not block public ACLs (NIST SC-7).", [r.name])
}

deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket_public_access_block"
  planned := r.change.after
  planned.block_public_policy == false
  msg := sprintf("S3 bucket public access block '%v' does not block public policies (NIST SC-7).", [r.name])
}

# --- SC-7: KMS keys must have rotation enabled ---
deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_kms_key"
  planned := r.change.after
  planned.enable_key_rotation == false
  msg := sprintf("KMS key '%v' does not have key rotation enabled (NIST SC-28).", [r.name])
}
