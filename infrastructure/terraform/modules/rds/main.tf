# RDS Module — PostgreSQL Multi-AZ with Encryption
# Controls: SC-28 (Protection of Information at Rest), SC-8 (Transmission Confidentiality)

resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-${var.environment}-postgres"

  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.medium"
  allocated_storage    = 50
  max_allocated_storage = 200

  db_name  = "anthra"
  username = "anthra_admin"
  manage_master_user_password = true # AWS manages rotation via Secrets Manager

  # Multi-AZ for FedRAMP resilience (CP-10)
  multi_az             = true
  db_subnet_group_name = "${var.project_name}-${var.environment}-db"

  # Encryption at rest (SC-28)
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  # Network isolation (SC-7)
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  # Backup (CP-9)
  backup_retention_period = 35 # FedRAMP: 30+ days
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  # Logging (AU-2, AU-12)
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Protection
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.project_name}-final-${formatdate("YYYY-MM-DD", timestamp())}"
  copy_tags_to_snapshot     = true

  # Performance
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn

  tags = { Name = "${var.project_name}-postgres" }
}

# --- KMS for RDS encryption ---

resource "aws_kms_key" "rds" {
  description             = "RDS encryption for ${var.project_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = { Name = "${var.project_name}-rds-kms" }
}

# --- Security Group ---

resource "aws_security_group" "rds" {
  name_prefix = "${var.project_name}-rds-"
  description = "RDS PostgreSQL — EKS pods only"
  vpc_id      = var.vpc_id

  tags = { Name = "${var.project_name}-rds-sg" }

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group_rule" "rds_ingress_eks" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.eks_security_group
  security_group_id        = aws_security_group.rds.id
  description              = "PostgreSQL from EKS worker nodes"
}

resource "aws_security_group_rule" "rds_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.rds.id
}
