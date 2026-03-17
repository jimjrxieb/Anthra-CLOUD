output "api_role_arn" {
  value = aws_iam_role.api_sa.arn
}

output "log_ingest_role_arn" {
  value = aws_iam_role.log_ingest_sa.arn
}
