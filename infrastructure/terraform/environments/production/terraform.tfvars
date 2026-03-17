# Anthra FedRAMP Moderate — Production Environment
# NIST 800-53: CM-6 (Configuration Settings)

project_name       = "anthra"
environment        = "production"
aws_region         = "us-east-1"
vpc_cidr           = "10.0.0.0/16"
eks_version        = "1.29"
node_min           = 3
node_max           = 6
node_desired       = 3
node_instance_type = "t3.large"
alert_email        = "security@anthra.cloud"
