# IAM Module — IRSA Roles for Anthra Service Accounts
# Controls: AC-2 (Account Management), AC-6 (Least Privilege)

# --- IRSA Role: API Service ---

resource "aws_iam_role" "api_sa" {
  name = "${var.project_name}-${var.environment}-api-sa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${var.eks_oidc_provider}"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${var.eks_oidc_provider}:sub" = "system:serviceaccount:anthra:anthra-api"
          "${var.eks_oidc_provider}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = { Name = "${var.project_name}-${var.environment}-api-irsa" }
}

# API can read secrets and write to S3 logs
resource "aws_iam_role_policy" "api_sa" {
  name = "api-service-policy"
  role = aws_iam_role.api_sa.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:${var.project_name}/${var.environment}/*"
      },
      {
        Sid    = "DecryptSecrets"
        Effect = "Allow"
        Action = ["kms:Decrypt"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.*.amazonaws.com"
          }
        }
      },
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "arn:aws:s3:::${var.project_name}-*-logs-*/api/*"
      }
    ]
  })
}

# --- IRSA Role: Log Ingest Service ---

resource "aws_iam_role" "log_ingest_sa" {
  name = "${var.project_name}-${var.environment}-log-ingest-sa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${var.eks_oidc_provider}"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${var.eks_oidc_provider}:sub" = "system:serviceaccount:anthra:anthra-log-ingest"
          "${var.eks_oidc_provider}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = { Name = "${var.project_name}-${var.environment}-log-ingest-irsa" }
}

# Log ingest writes to S3 and reads secrets
resource "aws_iam_role_policy" "log_ingest_sa" {
  name = "log-ingest-service-policy"
  role = aws_iam_role.log_ingest_sa.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadDBSecret"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:*:*:secret:${var.project_name}/${var.environment}/db-credentials*"
      },
      {
        Sid    = "WriteLogArchive"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = "arn:aws:s3:::${var.project_name}-*-logs-*/ingest/*"
      }
    ]
  })
}

data "aws_caller_identity" "current" {}
