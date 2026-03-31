output "cloudtrail_arn" {
  value = aws_cloudtrail.main.arn
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}

output "config_recorder_id" {
  value = aws_config_configuration_recorder.main.id
}

output "sns_topic_arn" {
  value = aws_sns_topic.cloudtrail_alerts.arn
}
