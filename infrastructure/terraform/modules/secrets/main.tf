# Secrets Manager Module — Credential Management
# Controls: IA-5(7) (No Embedded Authenticators), SC-28 (Protection at Rest)

resource "aws_secretsmanager_secret" "db_password" {
  name                    = "${var.project_name}/${var.environment}/db-credentials"
  description             = "Anthra PostgreSQL credentials"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.secrets.arn

  tags = { Name = "${var.project_name}-db-credentials" }
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = "anthra_admin"
    password = random_password.db.result
    engine   = "postgres"
    port     = 5432
  })
}

resource "random_password" "db" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# API keys
resource "aws_secretsmanager_secret" "api_keys" {
  name                    = "${var.project_name}/${var.environment}/api-keys"
  description             = "Anthra API authentication keys"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.secrets.arn

  tags = { Name = "${var.project_name}-api-keys" }
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id = aws_secretsmanager_secret.api_keys.id
  secret_string = jsonencode({
    jwt_secret = random_password.jwt.result
    api_key    = random_password.api_key.result
  })
}

resource "random_password" "jwt" {
  length  = 64
  special = false
}

resource "random_password" "api_key" {
  length  = 48
  special = false
}

# --- KMS for Secrets Manager ---

resource "aws_kms_key" "secrets" {
  description             = "Secrets Manager encryption for ${var.project_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = { Name = "${var.project_name}-secrets-kms" }
}

# --- Automatic Rotation (IA-5(1)) ---

resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id           = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.rotate_secret.arn

  rotation_rules {
    automatically_after_days = 90 # FedRAMP: rotate every 90 days
  }
}

# Rotation Lambda placeholder — deploy actual rotation function separately
resource "aws_lambda_function" "rotate_secret" {
  function_name = "${var.project_name}-${var.environment}-rotate-db-secret"
  role          = aws_iam_role.rotation_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 30

  # Placeholder zip — replace with actual rotation code
  filename = "${path.module}/rotate_placeholder.zip"

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      SECRET_ARN = aws_secretsmanager_secret.db_password.arn
    }
  }

  tags = { Name = "${var.project_name}-secret-rotation" }
}

resource "aws_iam_role" "rotation_lambda" {
  name = "${var.project_name}-${var.environment}-secret-rotation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "rotation_lambda" {
  name = "secret-rotation-policy"
  role = aws_iam_role.rotation_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage",
          "secretsmanager:DescribeSecret"
        ]
        Effect   = "Allow"
        Resource = aws_secretsmanager_secret.db_password.arn
      },
      {
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Effect   = "Allow"
        Resource = aws_kms_key.secrets.arn
      }
    ]
  })
}

resource "aws_lambda_permission" "secrets_manager" {
  statement_id  = "AllowSecretsManager"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotate_secret.function_name
  principal     = "secretsmanager.amazonaws.com"
  source_arn    = aws_secretsmanager_secret.db_password.arn
}
