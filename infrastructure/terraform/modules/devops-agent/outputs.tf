# Outputs for DevOps Agent module

output "agent_space_id" {
  description = "DevOps Agent Space ID"
  value       = awscc_devopsagent_agent_space.main.agent_space_id
}

output "agent_space_arn" {
  description = "DevOps Agent Space ARN"
  value       = awscc_devopsagent_agent_space.main.arn
}

output "agent_space_role_arn" {
  description = "IAM role ARN for the Agent Space"
  value       = aws_iam_role.agent_space.arn
}

output "webapp_role_arn" {
  description = "IAM role ARN for the Operator App (empty if disabled)"
  value       = var.enable_operator_app ? aws_iam_role.webapp[0].arn : ""
}
