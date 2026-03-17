# Root variables for Anthra FedRAMP Terraform deployment

variable "project_name" {
  type        = string
  description = "Project name used as prefix for all resources"
  default     = "anthra"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "production"
  validation {
    condition     = contains(["production", "staging", "dev"], var.environment)
    error_message = "Environment must be production, staging, or dev."
  }
}

variable "aws_region" {
  type        = string
  description = "AWS region for deployment"
  default     = "us-east-1"
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR block"
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "Must be a valid CIDR block."
  }
}

variable "eks_version" {
  type        = string
  description = "EKS Kubernetes version"
  default     = "1.29"
}

variable "node_min" {
  type        = number
  description = "Minimum number of EKS worker nodes"
  default     = 3
}

variable "node_max" {
  type        = number
  description = "Maximum number of EKS worker nodes"
  default     = 6
}

variable "node_desired" {
  type        = number
  description = "Desired number of EKS worker nodes"
  default     = 3
}

variable "node_instance_type" {
  type        = string
  description = "EC2 instance type for EKS worker nodes"
  default     = "t3.large"
}

variable "alert_email" {
  type        = string
  description = "Email for CloudWatch alarm notifications"
}
