output "log_bucket_name" {
  value = aws_s3_bucket.logs.bucket
}

output "log_bucket_arn" {
  value = aws_s3_bucket.logs.arn
}

output "evidence_bucket_name" {
  value = aws_s3_bucket.evidence.bucket
}

output "evidence_bucket_arn" {
  value = aws_s3_bucket.evidence.arn
}

output "access_logs_bucket_id" {
  value = aws_s3_bucket.access_logs.id
}
