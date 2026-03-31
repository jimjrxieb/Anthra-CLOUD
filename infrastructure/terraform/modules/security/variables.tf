variable "project_name" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "access_logs_bucket_id" {
  type        = string
  description = "S3 bucket ID for access logging (CKV_AWS_18)"
}
