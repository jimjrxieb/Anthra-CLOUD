output "endpoint" {
  value = aws_db_instance.main.endpoint
}

output "instance_id" {
  value = aws_db_instance.main.identifier
}

output "port" {
  value = aws_db_instance.main.port
}
