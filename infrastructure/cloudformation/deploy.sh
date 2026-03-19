#!/usr/bin/env bash
# Anthra Cloud — Deploy all CloudFormation stacks in order
# Usage: bash cloudformation/deploy.sh [--region us-east-1] [--email security@anthra.cloud]

set -euo pipefail

REGION="${1:---region}"
if [[ "$REGION" == "--region" ]]; then
  REGION="${2:-us-east-1}"
fi

EMAIL="${3:-security@anthra.cloud}"
PROJECT="anthra"
ENV="production"

echo "=== Anthra Cloud — CloudFormation Deployment ==="
echo "Region: $REGION"
echo "Email:  $EMAIL"
echo ""

# Stack 1: VPC
echo "[1/5] Deploying VPC stack..."
aws cloudformation deploy \
  --template-file cloudformation/01-vpc.yaml \
  --stack-name "${PROJECT}-vpc" \
  --parameter-overrides \
    ProjectName=$PROJECT \
    Environment=$ENV \
  --region "$REGION" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset
echo "  VPC deployed."

# Stack 2: Security
echo "[2/5] Deploying Security stack..."
aws cloudformation deploy \
  --template-file cloudformation/02-security.yaml \
  --stack-name "${PROJECT}-security" \
  --parameter-overrides \
    ProjectName=$PROJECT \
    Environment=$ENV \
  --region "$REGION" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset
echo "  Security deployed."

# Stack 3: EKS
echo "[3/5] Deploying EKS stack..."
aws cloudformation deploy \
  --template-file cloudformation/03-eks.yaml \
  --stack-name "${PROJECT}-eks" \
  --parameter-overrides \
    ProjectName=$PROJECT \
    Environment=$ENV \
  --region "$REGION" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset
echo "  EKS deployed. Waiting for cluster..."
aws eks wait cluster-active --name "${PROJECT}-eks" --region "$REGION" 2>/dev/null || true

# Stack 4: RDS + ElastiCache
echo "[4/5] Deploying Data stack (RDS + Redis)..."
aws cloudformation deploy \
  --template-file cloudformation/04-rds.yaml \
  --stack-name "${PROJECT}-data" \
  --parameter-overrides \
    ProjectName=$PROJECT \
    Environment=$ENV \
  --region "$REGION" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset
echo "  Data stack deployed."

# Stack 5: Monitoring
echo "[5/5] Deploying Monitoring stack..."
aws cloudformation deploy \
  --template-file cloudformation/05-monitoring.yaml \
  --stack-name "${PROJECT}-monitoring" \
  --parameter-overrides \
    ProjectName=$PROJECT \
    Environment=$ENV \
    AlertEmail=$EMAIL \
  --region "$REGION" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset
echo "  Monitoring deployed."

echo ""
echo "=== All stacks deployed ==="
echo ""
echo "Next steps:"
echo "  1. Update kubeconfig:"
echo "     aws eks update-kubeconfig --name ${PROJECT}-eks --region $REGION"
echo ""
echo "  2. Deploy K8s manifests:"
echo "     kubectl apply -f infrastructure/"
echo ""
echo "  3. Install ALB Ingress Controller:"
echo "     helm install aws-load-balancer-controller eks/aws-load-balancer-controller \\"
echo "       -n kube-system --set clusterName=${PROJECT}-eks"
