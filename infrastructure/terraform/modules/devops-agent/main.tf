# DevOps Agent Module — Autonomous Incident Investigation
# Deploys Agent Space, IAM roles, and account association
#
# Requires: hashicorp/awscc provider >= 1.66.0 (devopsagent resources)
# Constraint: us-east-1 only (AWS hard requirement during preview)
# Note: Operator App must be enabled via console/CLI after deploy (not in awscc provider)

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    awscc = {
      source  = "hashicorp/awscc"
      version = ">= 1.66.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# --- Agent Space (awscc provider) ---

resource "awscc_devopsagent_agent_space" "main" {
  agent_space_name = var.agent_space_name

  tags = [
    { key = "Name", value = var.agent_space_name },
    { key = "Project", value = var.project_name },
    { key = "Environment", value = var.environment },
  ]
}

# --- IAM Role: Agent Space (read-only investigation) ---

resource "aws_iam_role" "agent_space" {
  name = "${var.project_name}-${var.environment}-devops-agent-space"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "aidevops.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnLike = {
          "aws:SourceArn" = awscc_devopsagent_agent_space.main.arn
        }
      }
    }]
  })

  tags = { Name = "${var.project_name}-devops-agent-space-role" }
}

# AWS managed policy for investigation capabilities
resource "aws_iam_role_policy_attachment" "aiops_assistant" {
  role       = aws_iam_role.agent_space.name
  policy_arn = "arn:aws:iam::aws:policy/AIOpsAssistantPolicy"
}

# EKS admin view for cluster investigation
resource "aws_iam_role_policy_attachment" "eks_admin_view" {
  role       = aws_iam_role.agent_space.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSAdminViewPolicy"
}

# --- Account Association (awscc provider) ---

resource "awscc_devopsagent_association" "main" {
  agent_space_id = awscc_devopsagent_agent_space.main.agent_space_id
  account_id     = data.aws_caller_identity.current.account_id
  role_arn       = aws_iam_role.agent_space.arn

  depends_on = [
    aws_iam_role_policy_attachment.aiops_assistant,
    aws_iam_role_policy_attachment.eks_admin_view,
  ]
}

# --- IAM Role: Operator App (web UI access) ---
# Operator App itself is created via console/CLI post-deploy,
# but the IAM role can be pre-provisioned.

resource "aws_iam_role" "webapp" {
  count = var.enable_operator_app ? 1 : 0

  name = "${var.project_name}-${var.environment}-devops-agent-webapp"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "aidevops.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })

  tags = { Name = "${var.project_name}-devops-agent-webapp-role" }
}

resource "aws_iam_role_policy" "webapp" {
  count = var.enable_operator_app ? 1 : 0

  name = "devops-agent-webapp-policy"
  role = aws_iam_role.webapp[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DevOpsAgentOperator"
        Effect = "Allow"
        Action = [
          "aidevops:GetAgentSpace",
          "aidevops:ListAgentSpaces",
          "aidevops:InvokeAgent",
          "aidevops:ListExecutions",
          "aidevops:GetExecution",
          "aidevops:ListInvestigations",
          "aidevops:GetInvestigation",
          "aidevops:CreateBacklogTask",
          "aidevops:ListBacklogTasks",
          "aidevops:GetBacklogTask",
          "aidevops:DiscoverTopology"
        ]
        Resource = awscc_devopsagent_agent_space.main.arn
      }
    ]
  })
}
