# Anthra-CLOUD — Session 1 Deployment Runbook
## EKS Security Baseline: IRSA + KMS + VPC + GuardDuty + CloudTrail + Secrets Manager
### Package: 06-CLOUD-SECURITY | Before/After Portfolio: After State

---

## Session Goal

Deploy a production-grade EKS cluster that directly answers every finding
in the Anthra-FedRAMP BEFORE STATE banner:

```
BEFORE: No auth. No RBAC. XSS in search. API keys in plaintext. No audit trail.
AFTER:  IRSA. EKS Access Entries. Secrets Manager + KMS. CloudTrail. GuardDuty.
```

**Estimated AWS cost**: $8-12 for a 4-hour session
**Tear down**: Always at end of session — never leave running

---

## Prerequisites (Run Before Starting the Clock)

```bash
# Confirm tools installed
aws --version          # aws-cli v2
eksctl version         # 0.180+
kubectl version        # 1.29+
terraform version      # 1.7+
helm version           # 3.14+

# Confirm correct AWS account
aws sts get-caller-identity
# Verify: Account, UserId — make sure it's not prod

# Set your variables — fill these in once, use everywhere
export AWS_REGION="us-east-1"
export CLUSTER_NAME="anthra-cloud"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export K8S_VERSION="1.29"

echo "Account: $AWS_ACCOUNT_ID | Region: $AWS_REGION | Cluster: $CLUSTER_NAME"
```

---

## PHASE 1 — VPC and Network Foundation

**Why first**: Everything else lives inside the VPC.
Private subnets prevent direct internet access to nodes and API server.

```bash
# Create VPC with private subnets via Terraform
# Directory: infrastructure/anthra-cloud/01-vpc/

cat > main.tf << 'EOF'
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "anthra-cloud-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true   # cost optimization — one NAT for demo
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Required tags for EKS to discover subnets
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"             = 1
    "kubernetes.io/cluster/${var.cluster_name}"   = "owned"
  }

  public_subnet_tags = {
    "kubernetes.io/role/elb"                      = 1
    "kubernetes.io/cluster/${var.cluster_name}"   = "owned"
  }

  tags = {
    Project     = "anthra-cloud"
    Environment = "demo"
    ManagedBy   = "terraform"
  }
}

output "vpc_id"             { value = module.vpc.vpc_id }
output "private_subnet_ids" { value = module.vpc.private_subnets }
output "public_subnet_ids"  { value = module.vpc.public_subnets }
EOF

terraform init && terraform apply -auto-approve

# Save outputs
export VPC_ID=$(terraform output -raw vpc_id)
export PRIVATE_SUBNETS=$(terraform output -json private_subnet_ids | jq -r 'join(",")')
echo "VPC: $VPC_ID | Private Subnets: $PRIVATE_SUBNETS"
```

---

## PHASE 2 — KMS Key for Envelope Encryption

**Why**: Encrypts Kubernetes secrets at rest in etcd.
Without this, secrets stored in etcd are base64 — not encrypted.

```bash
# Create KMS key for EKS secrets encryption
aws kms create-key \
  --description "Anthra-CLOUD EKS secrets encryption" \
  --key-usage ENCRYPT_DECRYPT \
  --tags TagKey=Project,TagValue=anthra-cloud \
  --query 'KeyMetadata.KeyId' \
  --output text

export KMS_KEY_ID=$(aws kms list-keys --query 'Keys[0].KeyId' --output text)

# Create alias for easy reference
aws kms create-alias \
  --alias-name alias/anthra-cloud-eks \
  --target-key-id $KMS_KEY_ID

# Get the full ARN
export KMS_KEY_ARN=$(aws kms describe-key \
  --key-id alias/anthra-cloud-eks \
  --query 'KeyMetadata.Arn' \
  --output text)

echo "KMS Key ARN: $KMS_KEY_ARN"
```

---

## PHASE 3 — EKS Cluster Provisioning

**Why**: Core cluster with private API endpoint, KMS encryption,
CloudWatch logging, and OIDC provider for IRSA.

```bash
# Create cluster config
cat > cluster-config.yaml << EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
  version: "${K8S_VERSION}"
  tags:
    Project: anthra-cloud
    Environment: demo

# KMS encryption for secrets at rest
secretsEncryption:
  keyARN: ${KMS_KEY_ARN}

# VPC — use existing VPC from Phase 1
vpc:
  id: ${VPC_ID}
  subnets:
    private:
      us-east-1a:
        id: $(echo $PRIVATE_SUBNETS | cut -d',' -f1)
      us-east-1b:
        id: $(echo $PRIVATE_SUBNETS | cut -d',' -f2)

# Private API server — no public endpoint
privateCluster:
  enabled: false   # set true for full private — requires VPN/bastion
  # For demo: keep public endpoint but restrict to your IP
  # For prod Anthra-CLOUD: enable privateCluster

# CloudWatch control plane logging
cloudWatch:
  clusterLogging:
    enableTypes:
      - api
      - audit
      - authenticator
      - controllerManager
      - scheduler

# Node group — private subnets only
managedNodeGroups:
  - name: anthra-workers
    instanceType: t3.medium
    minSize: 1
    maxSize: 2
    desiredCapacity: 2
    privateNetworking: true     # nodes in private subnets only
    volumeSize: 20
    volumeEncrypted: true       # EBS volumes encrypted
    volumeKmsKeyID: ${KMS_KEY_ARN}
    tags:
      Project: anthra-cloud
    iam:
      withAddonPolicies:
        imageBuilder: false
        autoScaler: true
        cloudWatch: true
        albIngress: true
        ebs: true

# OIDC provider — required for IRSA
iam:
  withOIDC: true
EOF

# Deploy cluster — this takes 15-20 minutes
eksctl create cluster -f cluster-config.yaml

# Verify cluster is up
kubectl get nodes
kubectl cluster-info
```

---

## PHASE 4 — IRSA (IAM Roles for Service Accounts)

**Why**: IRSA = pod-level IAM. No static credentials.
Each pod gets its own temporary AWS credentials scoped to exactly what it needs.
This directly kills the "API keys in plaintext" BEFORE finding.

```bash
# Step 1 — Verify OIDC provider was created
aws iam list-open-id-connect-providers

# Get OIDC issuer URL
export OIDC_URL=$(aws eks describe-cluster \
  --name $CLUSTER_NAME \
  --query "cluster.identity.oidc.issuer" \
  --output text)
echo "OIDC URL: $OIDC_URL"

# Step 2 — Create IAM role for anthra-api service account
# This role allows anthra-api to read from Secrets Manager ONLY
cat > anthra-api-trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_URL#https://}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_URL#https://}:sub": "system:serviceaccount:anthra:anthra-api",
          "${OIDC_URL#https://}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF

# Create the role
aws iam create-role \
  --role-name anthra-api-irsa-role \
  --assume-role-policy-document file://anthra-api-trust-policy.json \
  --description "IRSA role for anthra-api — Secrets Manager read only"

# Create least-privilege policy — Secrets Manager read only
cat > anthra-api-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:anthra/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "${KMS_KEY_ARN}"
    }
  ]
}
EOF

# Attach policy to role
aws iam put-role-policy \
  --role-name anthra-api-irsa-role \
  --policy-name anthra-api-secrets-policy \
  --policy-document file://anthra-api-policy.json

# Step 3 — Create Kubernetes ServiceAccount with IRSA annotation
kubectl create namespace anthra

cat << EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: anthra-api
  namespace: anthra
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::${AWS_ACCOUNT_ID}:role/anthra-api-irsa-role
automountServiceAccountToken: false
EOF

# Step 4 — Verify IRSA is working
# Deploy a test pod using the SA and check it can reach Secrets Manager
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: irsa-test
  namespace: anthra
spec:
  serviceAccountName: anthra-api
  containers:
    - name: aws-cli
      image: amazon/aws-cli:latest
      command: ["sleep", "3600"]
  restartPolicy: Never
EOF

kubectl wait --for=condition=ready pod/irsa-test -n anthra --timeout=60s

# Test — this should succeed (pod can read secrets)
kubectl exec irsa-test -n anthra -- \
  aws secretsmanager list-secrets \
  --region $AWS_REGION \
  --query 'SecretList[].Name'

# Cleanup test pod
kubectl delete pod irsa-test -n anthra
```

---

## PHASE 5 — AWS Secrets Manager + KMS Integration

**Why**: Kills the "API keys in plaintext" finding permanently.
Secrets live in Secrets Manager, encrypted with KMS,
synced to Kubernetes via External Secrets Operator.

```bash
# Step 1 — Store Anthra app secrets in Secrets Manager
# Database credentials
aws secretsmanager create-secret \
  --name "anthra/prod/database" \
  --description "Anthra database credentials" \
  --kms-key-id $KMS_KEY_ARN \
  --secret-string '{
    "host": "anthra-db.internal",
    "port": "5432",
    "username": "anthra_app",
    "password": "'"$(openssl rand -base64 32)"'",
    "database": "anthra_prod"
  }'

# API keys
aws secretsmanager create-secret \
  --name "anthra/prod/api-keys" \
  --description "Anthra API keys" \
  --kms-key-id $KMS_KEY_ARN \
  --secret-string '{
    "jwt_secret": "'"$(openssl rand -base64 64)"'",
    "internal_api_key": "'"$(openssl rand -base64 32)"'"
  }'

# Step 2 — Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

helm install external-secrets \
  external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=\
arn:aws:iam::${AWS_ACCOUNT_ID}:role/anthra-api-irsa-role

# Step 3 — Create ClusterSecretStore pointing to AWS Secrets Manager
cat << EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-secrets-manager
spec:
  provider:
    aws:
      service: SecretsManager
      region: ${AWS_REGION}
      auth:
        jwt:
          serviceAccountRef:
            name: anthra-api
            namespace: anthra
EOF

# Step 4 — Create ExternalSecret for database credentials
cat << EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: anthra-db-creds
  namespace: anthra
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: anthra-db-creds
    creationPolicy: Owner
  data:
    - secretKey: host
      remoteRef:
        key: anthra/prod/database
        property: host
    - secretKey: username
      remoteRef:
        key: anthra/prod/database
        property: username
    - secretKey: password
      remoteRef:
        key: anthra/prod/database
        property: password
EOF

# Verify secret synced
kubectl get externalsecret -n anthra
kubectl get secret anthra-db-creds -n anthra
```

---

## PHASE 6 — CloudTrail Audit Logging

**Why**: Kills the "No audit trail" BEFORE finding.
Every API call — kubectl, AWS CLI, console — is logged with who, what, when.

```bash
# Create S3 bucket for CloudTrail logs
export TRAIL_BUCKET="anthra-cloud-cloudtrail-${AWS_ACCOUNT_ID}"

aws s3api create-bucket \
  --bucket $TRAIL_BUCKET \
  --region $AWS_REGION

# Block all public access
aws s3api put-public-access-block \
  --bucket $TRAIL_BUCKET \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Bucket policy — allow CloudTrail to write
cat > cloudtrail-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${TRAIL_BUCKET}"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${TRAIL_BUCKET}/AWSLogs/${AWS_ACCOUNT_ID}/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket $TRAIL_BUCKET \
  --policy file://cloudtrail-bucket-policy.json

# Create CloudTrail
aws cloudtrail create-trail \
  --name anthra-cloud-trail \
  --s3-bucket-name $TRAIL_BUCKET \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id $KMS_KEY_ARN

# Start logging
aws cloudtrail start-logging \
  --name anthra-cloud-trail

# Verify trail is active
aws cloudtrail get-trail-status \
  --name anthra-cloud-trail \
  --query '[IsLogging, LatestDeliveryTime]'

# Enable K8s API audit logs to CloudWatch (already done in eksctl config)
# Verify log group exists
aws logs describe-log-groups \
  --log-group-name-prefix /aws/eks/${CLUSTER_NAME} \
  --query 'logGroups[].logGroupName'
```

---

## PHASE 7 — GuardDuty Threat Detection

**Why**: Continuous threat detection for AWS account and EKS cluster.
Detects: crypto mining, credential theft, unusual API calls, suspicious pod behavior.

```bash
# Enable GuardDuty for the account
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES

export DETECTOR_ID=$(aws guardduty list-detectors \
  --query 'DetectorIds[0]' \
  --output text)

echo "GuardDuty Detector ID: $DETECTOR_ID"

# Enable EKS Protection — runtime threat detection for Kubernetes
aws guardduty update-detector \
  --detector-id $DETECTOR_ID \
  --features '[
    {
      "Name": "EKS_AUDIT_LOGS",
      "Status": "ENABLED"
    },
    {
      "Name": "EKS_RUNTIME_MONITORING",
      "Status": "ENABLED",
      "AdditionalConfiguration": [
        {
          "Name": "EKS_ADDON_MANAGEMENT",
          "Status": "ENABLED"
        }
      ]
    }
  ]'

# Create SNS topic for GuardDuty findings alerts
aws sns create-topic --name anthra-cloud-guardduty-alerts

export SNS_ARN=$(aws sns list-topics \
  --query 'Topics[?contains(TopicArn, `guardduty`)].TopicArn | [0]' \
  --output text)

# Create EventBridge rule to alert on HIGH/CRITICAL findings
aws events put-rule \
  --name anthra-cloud-guardduty-high \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [7, 7.0, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9,
                   8, 8.0, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 9, 10]
    }
  }' \
  --state ENABLED

# Verify GuardDuty is active
aws guardduty get-detector \
  --detector-id $DETECTOR_ID \
  --query '[Status, FindingPublishingFrequency]'
```

---

## PHASE 8 — EKS Access Entries (RBAC)

**Why**: Kills the "No RBAC" BEFORE finding.
EKS Access Entries replace the old aws-auth ConfigMap.
Proper role-based access — no cluster-admin for everyone.

```bash
# Step 1 — Create admin access entry for your IAM user
aws eks create-access-entry \
  --cluster-name $CLUSTER_NAME \
  --principal-arn arn:aws:iam::${AWS_ACCOUNT_ID}:user/$(aws iam get-user --query 'User.UserName' --output text) \
  --type STANDARD

# Associate admin policy to your user
aws eks associate-access-policy \
  --cluster-name $CLUSTER_NAME \
  --principal-arn arn:aws:iam::${AWS_ACCOUNT_ID}:user/$(aws iam get-user --query 'User.UserName' --output text) \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy \
  --access-scope type=cluster

# Step 2 — Create read-only access entry for developers
# (In real client engagement — this would be a developer IAM role)
aws iam create-role \
  --role-name anthra-cloud-developer-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'"${AWS_ACCOUNT_ID}"':root"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws eks create-access-entry \
  --cluster-name $CLUSTER_NAME \
  --principal-arn arn:aws:iam::${AWS_ACCOUNT_ID}:role/anthra-cloud-developer-role \
  --type STANDARD \
  --kubernetes-groups developers

aws eks associate-access-policy \
  --cluster-name $CLUSTER_NAME \
  --principal-arn arn:aws:iam::${AWS_ACCOUNT_ID}:role/anthra-cloud-developer-role \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy \
  --access-scope type=namespace \
  --access-scope namespaces=anthra

# Step 3 — Verify access entries
aws eks list-access-entries \
  --cluster-name $CLUSTER_NAME

# Step 4 — Apply Kyverno policies from golden path
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace

# Apply baseline PSS policies
kubectl label namespace anthra \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

---

## PHASE 9 — CloudWatch Container Insights

**Why**: Real usage data for cost optimization story.
Shows actual CPU/memory vs provisioned — the 80% waste problem made visible.

```bash
# Install CloudWatch agent for Container Insights
aws eks create-addon \
  --cluster-name $CLUSTER_NAME \
  --addon-name amazon-cloudwatch-observability \
  --service-account-role-arn arn:aws:iam::${AWS_ACCOUNT_ID}:role/anthra-api-irsa-role

# Verify addon is active
aws eks describe-addon \
  --cluster-name $CLUSTER_NAME \
  --addon-name amazon-cloudwatch-observability \
  --query 'addon.status'

# Create CloudWatch dashboard for cost visibility
aws cloudwatch put-dashboard \
  --dashboard-name AnthraCostOptimization \
  --dashboard-body '{
    "widgets": [
      {
        "type": "metric",
        "properties": {
          "metrics": [
            ["ContainerInsights", "pod_cpu_utilization", "ClusterName", "anthra-cloud"],
            ["ContainerInsights", "pod_memory_utilization", "ClusterName", "anthra-cloud"]
          ],
          "title": "Pod CPU vs Memory Utilization",
          "period": 300
        }
      },
      {
        "type": "metric",
        "properties": {
          "metrics": [
            ["ContainerInsights", "node_cpu_utilization", "ClusterName", "anthra-cloud"],
            ["ContainerInsights", "node_memory_utilization", "ClusterName", "anthra-cloud"]
          ],
          "title": "Node Utilization — Right-Sizing Target",
          "period": 300
        }
      }
    ]
  }'

echo "Dashboard URL:"
echo "https://${AWS_REGION}.console.aws.amazon.com/cloudwatch/home?region=${AWS_REGION}#dashboards:name=AnthraCostOptimization"
```

---

## PHASE 10 — Verification and Screenshots

**This is the portfolio evidence. Screenshot everything.**

```bash
# 1. Cluster running with private networking
aws eks describe-cluster \
  --name $CLUSTER_NAME \
  --query 'cluster.[name,status,version,resourcesVpcConfig,encryptionConfig]'

# 2. KMS encryption active
aws eks describe-cluster \
  --name $CLUSTER_NAME \
  --query 'cluster.encryptionConfig'
# Should show KMS key ARN against secrets resources

# 3. IRSA working
kubectl get serviceaccount anthra-api -n anthra -o yaml
# Should show eks.amazonaws.com/role-arn annotation

# 4. External secrets syncing
kubectl get externalsecret -n anthra
kubectl get secret anthra-db-creds -n anthra
# Type should be Opaque — populated from Secrets Manager

# 5. GuardDuty active
aws guardduty get-detector --detector-id $DETECTOR_ID
# Status: ENABLED

# 6. CloudTrail logging
aws cloudtrail get-trail-status --name anthra-cloud-trail
# IsLogging: true

# 7. Access entries (RBAC)
aws eks list-access-entries --cluster-name $CLUSTER_NAME --output table

# 8. PSS enforced on namespaces
kubectl get namespace anthra --show-labels
# Should show pod-security labels

# 9. CloudWatch log groups
aws logs describe-log-groups \
  --log-group-name-prefix /aws/eks/${CLUSTER_NAME}

# 10. Node utilization baseline (take this screenshot — use in portfolio)
kubectl top nodes
kubectl top pods -n anthra
```

---

## PHASE 11 — TEAR DOWN (Do Not Skip)

```bash
# Delete in reverse order — always clean up

# 1. Delete EKS cluster (takes 10-15 min)
eksctl delete cluster --name $CLUSTER_NAME --region $AWS_REGION

# 2. Disable GuardDuty
aws guardduty delete-detector --detector-id $DETECTOR_ID

# 3. Delete CloudTrail
aws cloudtrail stop-logging --name anthra-cloud-trail
aws cloudtrail delete-trail --name anthra-cloud-trail

# 4. Delete S3 bucket (must be empty first)
aws s3 rm s3://$TRAIL_BUCKET --recursive
aws s3api delete-bucket --bucket $TRAIL_BUCKET

# 5. Delete KMS key (schedule for deletion — 7 day minimum)
aws kms schedule-key-deletion \
  --key-id $KMS_KEY_ID \
  --pending-window-in-days 7

# 6. Delete IAM roles
aws iam delete-role-policy \
  --role-name anthra-api-irsa-role \
  --policy-name anthra-api-secrets-policy
aws iam delete-role --role-name anthra-api-irsa-role

# 7. Delete Secrets Manager secrets
aws secretsmanager delete-secret \
  --secret-id anthra/prod/database \
  --force-delete-without-recovery
aws secretsmanager delete-secret \
  --secret-id anthra/prod/api-keys \
  --force-delete-without-recovery

# 8. Delete VPC (Terraform)
cd infrastructure/anthra-cloud/01-vpc/
terraform destroy -auto-approve

# Verify nothing is running
aws eks list-clusters
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=anthra-cloud" \
  --query 'Reservations[].Instances[].[InstanceId,State.Name]'
```

---

## Before/After Evidence Summary

| BEFORE (Anthra-FedRAMP) | Control | AFTER (Anthra-CLOUD) | Evidence |
|---|---|---|---|
| No auth | IA-2 | EKS Access Entries + IRSA | `aws eks list-access-entries` |
| No RBAC | AC-2 | Per-workload ServiceAccounts + Access Policies | `kubectl get sa -n anthra` |
| API keys in plaintext | IA-5 | Secrets Manager + KMS + ExternalSecrets | `kubectl get externalsecret` |
| No audit trail | AU-2 | CloudTrail + EKS audit logs → CloudWatch | Trail status + log groups |
| XSS in search | SI-10 | Fixed in 01-APP-SEC (SAST findings resolved) | Rescan report |
| 36% compliance | CA-2 | Full security baseline deployed | Dashboard screenshot |

---

## Resume Bullet This Session Generates

```
Deployed production EKS cluster with full AWS security baseline:
IRSA (pod-level IAM), KMS envelope encryption, CloudTrail audit logging,
GuardDuty threat detection, and Secrets Manager integration — resolving
all critical findings from pre-hardening state and achieving NIST 800-53
control coverage across AC, IA, AU, and SI control families.
```

*Last updated: March 2026 | Anthra-CLOUD Session 1 | 06-CLOUD-SECURITY package*