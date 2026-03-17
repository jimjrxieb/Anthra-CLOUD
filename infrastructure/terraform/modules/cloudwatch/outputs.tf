output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "eks_log_group" {
  value = aws_cloudwatch_log_group.eks.name
}

output "app_log_group" {
  value = aws_cloudwatch_log_group.application.name
}
