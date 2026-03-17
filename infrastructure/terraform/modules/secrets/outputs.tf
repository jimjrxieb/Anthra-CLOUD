output "db_password_arn" {
  value = aws_secretsmanager_secret.db_password.arn
}

output "api_keys_arn" {
  value = aws_secretsmanager_secret.api_keys.arn
}

output "kms_key_arn" {
  value = aws_kms_key.secrets.arn
}
