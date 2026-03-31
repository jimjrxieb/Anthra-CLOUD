# Variables for DevOps Agent module

variable "project_name" {
  type        = string
  description = "Project name used as prefix for all resources"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
}

variable "agent_space_name" {
  type        = string
  description = "Name for the DevOps Agent Space"
}

variable "enable_operator_app" {
  type        = bool
  description = "Enable the web-based Operator App interface"
  default     = true
}

variable "auth_flow" {
  type        = string
  description = "Authentication flow for Operator App (iam or idc)"
  default     = "iam"
  validation {
    condition     = contains(["iam", "idc"], var.auth_flow)
    error_message = "Auth flow must be iam or idc."
  }
}
