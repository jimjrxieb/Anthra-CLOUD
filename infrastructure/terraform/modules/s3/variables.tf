variable "project_name" { type = string }
variable "environment" { type = string }
variable "aws_region" { type = string }
variable "sns_topic_arn" {
  type        = string
  description = "SNS topic ARN for S3 event notifications (CKV2_AWS_62, NIST AU-2)"
}
