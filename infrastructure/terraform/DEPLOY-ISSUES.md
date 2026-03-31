# Terraform Deploy Issues — Staging (2026-03-30)

Lessons from deploying `anthra-staging` to `us-east-1`. All caused by orphaned state from a prior partial `terraform destroy`.

---

## Issue 1: KMS Key Pending Deletion

**Error:** `DecryptionFailure: arn:aws:kms:...key/d63908df-... is pending deletion`

**Cause:** Previous `terraform destroy` scheduled the Secrets Manager KMS key for deletion (7-day window). Secrets still existed but couldn't be decrypted or updated.

**Fix:**
```bash
aws kms cancel-key-deletion --key-id d63908df-4819-4542-aa6a-f249e25d081f
aws kms enable-key --key-id d63908df-4819-4542-aa6a-f249e25d081f
```

**Prevention:** Before running `terraform destroy`, check for KMS keys with deletion windows. Consider using `deletion_window_in_days = 30` for production.

---

## Issue 2: Orphaned Resources Not in State

**Error:** `ResourceAlreadyExistsException: The specified log group already exists`

**Cause:** Previous destroy removed resources from state but AWS retained them (CloudWatch Log Groups, Secrets Manager secrets with recovery windows).

**Affected resources:**
- `/aws/cloudtrail/anthra-staging` (CloudWatch Log Group)
- `/aws/vpc/flow-logs/anthra-staging` (CloudWatch Log Group)
- `/aws/eks/anthra-staging-eks/cluster` (CloudWatch Log Group)
- `anthra/staging/db-credentials` (Secrets Manager)
- `anthra/staging/api-keys` (Secrets Manager)

**Fix:**
```bash
# Restore secrets from deletion schedule
aws secretsmanager restore-secret --secret-id "anthra/staging/db-credentials"
aws secretsmanager restore-secret --secret-id "anthra/staging/api-keys"

# Import all orphans into state
terraform import 'module.secrets.aws_secretsmanager_secret.db_password' 'anthra/staging/db-credentials'
terraform import 'module.secrets.aws_secretsmanager_secret.api_keys' 'anthra/staging/api-keys'
terraform import 'module.security.aws_cloudwatch_log_group.cloudtrail' '/aws/cloudtrail/anthra-staging'
terraform import 'module.vpc.aws_cloudwatch_log_group.flow_logs' '/aws/vpc/flow-logs/anthra-staging'
terraform import 'module.cloudwatch.aws_cloudwatch_log_group.eks' '/aws/eks/anthra-staging-eks/cluster'
```

**Prevention:** After `terraform destroy`, check for retained resources:
```bash
aws logs describe-log-groups --log-group-name-prefix "/aws/eks/anthra-" --query 'logGroups[].logGroupName'
aws secretsmanager list-secrets --filter Key=name,Values=anthra/ --query 'SecretList[].Name'
```

---

## Issue 3: Lambda DLQ Missing SQS Permissions

**Error:** `InvalidParameterValueException: The provided execution role does not have permissions to call SendMessage on SQS`

**Cause:** The Lambda rotation function's IAM role had Secrets Manager and KMS permissions but was missing `sqs:SendMessage` for its Dead Letter Queue. AWS validates DLQ access at function creation time.

**Fix:** Added to `modules/secrets/main.tf` rotation_lambda policy:
```hcl
{
  Action   = "sqs:SendMessage"
  Effect   = "Allow"
  Resource = aws_sqs_queue.lambda_dlq.arn
}
```

**Prevention:** Any Lambda with `dead_letter_config` requires `sqs:SendMessage` on the DLQ in its execution role. Checkov doesn't catch this — add to pre-deploy checklist.

---

## Issue 4: EKS Node Security Group Output Null

**Error:** `waiting for Security Group Rule create: couldn't find resource` (4+ minute timeout)

**Cause:** The EKS module output `node_security_group_id` used `aws_eks_node_group.main.resources[0].remote_access_security_group_id`, which is `null` when remote SSH access is not configured on the managed node group. The RDS ingress rule referenced this null SG ID.

**Fix:** Changed `modules/eks/outputs.tf`:
```hcl
# Before (null when no remote access configured):
output "node_security_group_id" {
  value = aws_eks_node_group.main.resources[0].remote_access_security_group_id
}

# After (always populated — the EKS-managed cluster SG):
output "node_security_group_id" {
  value = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
}
```

**Prevention:** Never use `remote_access_security_group_id` unless remote access is explicitly configured. Use `cluster_security_group_id` for inter-service communication.

---

## Issue 5: S3 Notification Before SNS Policy

**Error:** `Unable to validate the following destination configurations`

**Cause:** S3 bucket notifications tried to subscribe to the SNS topic before the SNS topic policy was updated to allow `s3.amazonaws.com` to publish.

**Fix:** Added S3 principal to SNS topic policy in `modules/security/main.tf`:
```hcl
{
  Sid       = "AllowS3Publish"
  Effect    = "Allow"
  Principal = { Service = "s3.amazonaws.com" }
  Action    = "SNS:Publish"
  Resource  = aws_sns_topic.cloudtrail_alerts.arn
}
```

**Prevention:** SNS topic policies must allow the publishing service BEFORE any S3 notification resource references the topic. Terraform usually handles ordering, but cross-module dependencies can race.
