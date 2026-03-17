variable "project_name" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "private_subnets" { type = list(string) }
variable "public_subnets" { type = list(string) }
variable "eks_version" { type = string }
variable "node_min" { type = number }
variable "node_max" { type = number }
variable "node_desired" { type = number }
variable "node_instance" { type = string }
variable "allowed_cidr_blocks" {
  type        = list(string)
  description = "CIDR blocks allowed to access EKS public endpoint"
  default     = []
}
