# Anthra Security Platform — FedRAMP Moderate Terraform Root
# NIST 800-53 Rev 5 controls implemented via IaC
#
# Usage:
#   cd terraform/
#   terraform init
#   terraform plan -var-file="environments/production/terraform.tfvars"
#   terraform apply -var-file="environments/production/terraform.tfvars"

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Remote state — create this bucket + table first:
  #   aws s3api create-bucket --bucket anthra-fedramp-tfstate --region us-east-1
  #   aws dynamodb create-table --table-name anthra-fedramp-tflock \
  #     --attribute-definitions AttributeName=LockID,AttributeType=S \
  #     --key-schema AttributeName=LockID,KeyType=HASH \
  #     --billing-mode PAY_PER_REQUEST
  backend "s3" {
    bucket         = "anthra-fedramp-tfstate"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "anthra-fedramp-tflock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "anthra-fedramp"
      Environment = var.environment
      ManagedBy   = "terraform"
      Compliance  = "FedRAMP-Moderate"
      Owner       = "guidepoint-security"
    }
  }
}

# --- Modules ---

module "vpc" {
  source = "./modules/vpc"

  project_name = var.project_name
  environment  = var.environment
  vpc_cidr     = var.vpc_cidr
  aws_region   = var.aws_region
}

module "security" {
  source = "./modules/security"

  project_name = var.project_name
  environment  = var.environment
  vpc_id       = module.vpc.vpc_id
}

module "iam" {
  source = "./modules/iam"

  project_name       = var.project_name
  environment        = var.environment
  eks_cluster_arn    = module.eks.cluster_arn
  eks_oidc_provider  = module.eks.oidc_provider
}

module "secrets" {
  source = "./modules/secrets"

  project_name = var.project_name
  environment  = var.environment
}

module "rds" {
  source = "./modules/rds"

  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  database_subnets   = module.vpc.database_subnet_ids
  db_password_secret = module.secrets.db_password_arn
  eks_security_group = module.eks.node_security_group_id
}

module "s3" {
  source = "./modules/s3"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region
}

module "eks" {
  source = "./modules/eks"

  project_name    = var.project_name
  environment     = var.environment
  vpc_id          = module.vpc.vpc_id
  private_subnets = module.vpc.private_subnet_ids
  public_subnets  = module.vpc.public_subnet_ids
  eks_version     = var.eks_version
  node_min        = var.node_min
  node_max        = var.node_max
  node_desired    = var.node_desired
  node_instance   = var.node_instance_type
}

module "cloudwatch" {
  source = "./modules/cloudwatch"

  project_name     = var.project_name
  environment      = var.environment
  eks_cluster_name = module.eks.cluster_name
  rds_instance_id  = module.rds.instance_id
  vpc_id           = module.vpc.vpc_id
  alert_email      = var.alert_email
}
