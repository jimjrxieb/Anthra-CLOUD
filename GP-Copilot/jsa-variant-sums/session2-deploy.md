# Anthra-CLOUD — Session 2 Deployment Runbook
## Cost Optimization Layer: Karpenter + HPA + VPA + Graviton + Resource Tagging
### Package: 06-CLOUD-SECURITY | Cost Optimization Story

---

## Session Goal

Add the cost optimization layer on top of Session 1's security baseline.
Generate real utilization data that proves the 80% waste problem is solved.

**Run Session 1 first. This builds on top of it.**
**Estimated AWS cost**: $10-15 (slightly longer — load testing for metrics)
**Tear down**: At end of session — same rules apply

---

## Prerequisites

```bash
# Confirm Session 1 cluster is still running OR redeploy it
aws eks describe-cluster \
  --name anthra-cloud \
  --query 'cluster.status'
# Must show: ACTIVE

# Re-export variables if new terminal
export AWS_REGION="us-east-1"
export CLUSTER_NAME="anthra-cloud"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export KMS_KEY_ARN=$(aws kms describe-key \
  --key-id alias/anthra-cloud-eks \
  --query 'KeyMetadata.Arn' \
  --output text)

# Confirm kubectl is pointed at the right cluster
kubectl config current-context
kubectl get nodes
```

---

## PHASE 1 — Baseline Metrics Before Optimization

**Why**: You need a before snapshot to prove optimization worked.
Numbers without a baseline mean nothing. Baseline first — always.

```bash
# Take baseline node utilization screenshot
echo "=== BASELINE — BEFORE OPTIMIZATION ==="
echo "Timestamp: $(date)"
kubectl top nodes
echo ""
kubectl top pods -A
echo ""

# Check what's actually provisioned vs used
kubectl describe nodes | grep -A8 "Allocated resources"

# Get exact numbers — save these
kubectl top nodes --no-headers | \
  awk '{print "Node: " $1 " | CPU: " $2 " | CPU%: " $3 " | Memory: " $4 " | Mem%: " $5}'

# Check current resource requests vs limits on all pods
kubectl get pods -A -o json | \
  jq -r '.items[] |
  select(.spec.containers[].resources.requests != null) |
  .metadata.namespace + "/" + .metadata.name + " | CPU req: " +
  (.spec.containers[0].resources.requests.cpu // "none") + " | Mem req: " +
  (.spec.containers[0].resources.requests.memory // "none")'

# Screenshot this output — it's your BEFORE state for Session 3
```

---

## PHASE 2 — Karpenter Installation

**Why**: Karpenter replaces Cluster Autoscaler.
It's smarter — it provisions exactly the right node for pending pods,
uses Spot instances automatically, and terminates empty nodes instantly.
This is the primary driver of node cost reduction.

```bash
# Step 1 — Set Karpenter version
export KARPENTER_VERSION="v0.37.0"
export KARPENTER_NAMESPACE="kube-system"

# Step 2 — Create Karpenter IAM role
cat > karpenter-trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/$(aws eks describe-cluster \
          --name $CLUSTER_NAME \
          --query "cluster.identity.oidc.issuer" \
          --output text | sed 's|https://||')"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "$(aws eks describe-cluster \
            --name $CLUSTER_NAME \
            --query "cluster.identity.oidc.issuer" \
            --output text | sed 's|https://||'):sub":
            "system:serviceaccount:${KARPENTER_NAMESPACE}:karpenter"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name KarpenterControllerRole-${CLUSTER_NAME} \
  --assume-role-policy-document file://karpenter-trust-policy.json

# Karpenter controller policy
cat > karpenter-controller-policy.json << EOF
{
  "Statement": [
    {
      "Action": [
        "ssm:GetParameter",
        "ec2:DescribeImages",
        "ec2:RunInstances",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeInstanceTypeOfferings",
        "ec2:DescribeAvailabilityZones",
        "ec2:DeleteLaunchTemplate",
        "ec2:CreateTags",
        "ec2:CreateLaunchTemplate",
        "ec2:CreateFleet",
        "ec2:DescribeSpotPriceHistory",
        "pricing:GetProducts"
      ],
      "Effect": "Allow",
      "Resource": "*",
      "Sid": "Karpenter"
    },
    {
      "Action": "ec2:TerminateInstances",
      "Condition": {
        "StringLike": {
          "ec2:ResourceTag/karpenter.sh/nodepool": "*"
        }
      },
      "Effect": "Allow",
      "Resource": "*",
      "Sid": "ConditionalEC2Termination"
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/KarpenterNodeRole-${CLUSTER_NAME}",
      "Sid": "PassNodeIAMRole"
    },
    {
      "Effect": "Allow",
      "Action": "eks:DescribeCluster",
      "Resource": "arn:aws:eks:${AWS_REGION}:${AWS_ACCOUNT_ID}:cluster/${CLUSTER_NAME}",
      "Sid": "EKSClusterEndpointLookup"
    }
  ],
  "Version": "2012-10-17"
}
EOF

aws iam put-role-policy \
  --role-name KarpenterControllerRole-${CLUSTER_NAME} \
  --policy-name KarpenterControllerPolicy \
  --policy-document file://karpenter-controller-policy.json

# Create node IAM role for Karpenter-provisioned nodes
aws iam create-role \
  --role-name KarpenterNodeRole-${CLUSTER_NAME} \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach required policies to node role
for policy in \
  AmazonEKSWorkerNodePolicy \
  AmazonEKS_CNI_Policy \
  AmazonEC2ContainerRegistryReadOnly \
  AmazonSSMManagedInstanceCore; do
  aws iam attach-role-policy \
    --role-name KarpenterNodeRole-${CLUSTER_NAME} \
    --policy-arn arn:aws:iam::aws:policy/${policy}
done

# Create instance profile
aws iam create-instance-profile \
  --instance-profile-name KarpenterNodeRole-${CLUSTER_NAME}
aws iam add-role-to-instance-profile \
  --instance-profile-name KarpenterNodeRole-${CLUSTER_NAME} \
  --role-name KarpenterNodeRole-${CLUSTER_NAME}

# Step 3 — Tag subnets and security groups for Karpenter discovery
NODEGROUP_SG=$(aws eks describe-cluster \
  --name $CLUSTER_NAME \
  --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId' \
  --output text)

aws ec2 create-tags \
  --resources $NODEGROUP_SG \
  --tags "Key=karpenter.sh/discovery,Value=${CLUSTER_NAME}"

# Tag private subnets
for subnet in $(aws ec2 describe-subnets \
  --filters "Name=tag:kubernetes.io/cluster/${CLUSTER_NAME},Values=owned" \
  --query 'Subnets[].SubnetId' --output text); do
  aws ec2 create-tags \
    --resources $subnet \
    --tags "Key=karpenter.sh/discovery,Value=${CLUSTER_NAME}"
done

# Step 4 — Add Karpenter to EKS access entries
aws eks create-access-entry \
  --cluster-name $CLUSTER_NAME \
  --principal-arn arn:aws:iam::${AWS_ACCOUNT_ID}:role/KarpenterNodeRole-${CLUSTER_NAME} \
  --type EC2_LINUX

# Step 5 — Install Karpenter via Helm
helm registry logout public.ecr.aws 2>/dev/null || true

helm upgrade --install karpenter oci://public.ecr.aws/karpenter/karpenter \
  --version "${KARPENTER_VERSION}" \
  --namespace "${KARPENTER_NAMESPACE}" \
  --create-namespace \
  --set "settings.clusterName=${CLUSTER_NAME}" \
  --set "settings.interruptionQueue=${CLUSTER_NAME}" \
  --set controller.resources.requests.cpu=1 \
  --set controller.resources.requests.memory=1Gi \
  --set controller.resources.limits.cpu=1 \
  --set controller.resources.limits.memory=1Gi \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=\
arn:aws:iam::${AWS_ACCOUNT_ID}:role/KarpenterControllerRole-${CLUSTER_NAME} \
  --wait

# Verify Karpenter is running
kubectl get pods -n $KARPENTER_NAMESPACE -l app.kubernetes.io/name=karpenter
```

---

## PHASE 3 — Karpenter NodePool Configuration

**Why**: NodePool tells Karpenter what types of nodes to provision.
We configure it to prefer Graviton (ARM) + Spot instances for 40-60% cost reduction.

```bash
# NodePool — mixed on-demand and spot, prefers Graviton
cat << EOF | kubectl apply -f -
apiVersion: karpenter.sh/v1beta1
kind: NodePool
metadata:
  name: anthra-default
spec:
  template:
    metadata:
      labels:
        managed-by: karpenter
        project: anthra-cloud
    spec:
      nodeClassRef:
        apiVersion: karpenter.k8s.aws/v1beta1
        kind: EC2NodeClass
        name: anthra-nodeclass

      # Allow both on-demand and spot
      requirements:
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["spot", "on-demand"]

        # Prefer Graviton (ARM) — 40% cheaper than x86
        - key: kubernetes.io/arch
          operator: In
          values: ["arm64", "amd64"]

        # Right-sized instance families only
        - key: karpenter.k8s.aws/instance-family
          operator: In
          values: ["t4g", "m7g", "c7g", "t3", "m5", "c5"]

        # Cap instance size — no over-provisioning
        - key: karpenter.k8s.aws/instance-size
          operator: In
          values: ["small", "medium", "large"]

  # Cost optimization — consolidate pods, terminate empty nodes
  disruption:
    consolidationPolicy: WhenUnderutilized
    consolidateAfter: 30s       # terminate empty nodes after 30s
    expireAfter: 720h           # recycle nodes every 30 days

  # Hard limits — prevent runaway scaling
  limits:
    cpu: "16"
    memory: 32Gi
---
apiVersion: karpenter.k8s.aws/v1beta1
kind: EC2NodeClass
metadata:
  name: anthra-nodeclass
spec:
  amiFamily: AL2023
  role: KarpenterNodeRole-${CLUSTER_NAME}

  # Private subnets only — no public IPs on nodes
  subnetSelectorTerms:
    - tags:
        karpenter.sh/discovery: "${CLUSTER_NAME}"

  securityGroupSelectorTerms:
    - tags:
        karpenter.sh/discovery: "${CLUSTER_NAME}"

  # EBS encryption — KMS key
  blockDeviceMappings:
    - deviceName: /dev/xvda
      ebs:
        volumeSize: 20Gi
        volumeType: gp3
        encrypted: true
        kmsKeyID: ${KMS_KEY_ARN}

  tags:
    Project: anthra-cloud
    ManagedBy: karpenter
EOF

# Verify NodePool created
kubectl get nodepool anthra-default
kubectl get ec2nodeclass anthra-nodeclass
```

---

## PHASE 4 — Horizontal Pod Autoscaler (HPA)

**Why**: HPA scales pod replicas based on actual CPU/memory.
Means you run minimum pods at low traffic, scale up automatically at peak.
No manual intervention, no over-provisioning for expected peaks.

```bash
# Install metrics-server (required for HPA)
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Verify metrics-server is running
kubectl get pods -n kube-system -l k8s-app=metrics-server

# Deploy anthra-api with HPA
cat << EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: anthra-api
  namespace: anthra
  labels:
    app: anthra-api
    project: anthra-cloud
spec:
  replicas: 1          # start with 1 — HPA will scale up
  selector:
    matchLabels:
      app: anthra-api
  template:
    metadata:
      labels:
        app: anthra-api
    spec:
      serviceAccountName: anthra-api
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: anthra-api
          image: ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/anthra-api:latest
          ports:
            - containerPort: 8080
          # Tight resource requests — right-sized not over-provisioned
          resources:
            requests:
              cpu: "100m"       # 0.1 CPU — what it actually uses at idle
              memory: "128Mi"
            limits:
              cpu: "500m"       # burst to 0.5 CPU under load
              memory: "256Mi"
          # Readiness before receiving traffic
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: anthra-api-hpa
  namespace: anthra
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: anthra-api
  minReplicas: 1      # never below 1
  maxReplicas: 5      # never above 5 — cost protection
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70    # scale up when CPU hits 70%
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80    # scale up when memory hits 80%
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60     # wait 60s before scaling up
      policies:
        - type: Pods
          value: 2
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300    # wait 5 min before scaling down
      policies:
        - type: Pods
          value: 1
          periodSeconds: 60
EOF

# Verify HPA created
kubectl get hpa -n anthra
kubectl describe hpa anthra-api-hpa -n anthra
```

---

## PHASE 5 — Vertical Pod Autoscaler (VPA)

**Why**: VPA watches actual usage and recommends right-sized requests.
This is the data that proves you solved the 80% waste problem.
VPA in recommendation mode — it advises, doesn't auto-apply (safer for demo).

```bash
# Install VPA
git clone https://github.com/kubernetes/autoscaler.git /tmp/autoscaler 2>/dev/null || true
bash /tmp/autoscaler/vertical-pod-autoscaler/hack/vpa-up.sh

# Create VPA for anthra-api in recommendation mode
cat << EOF | kubectl apply -f -
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: anthra-api-vpa
  namespace: anthra
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: anthra-api
  updatePolicy:
    updateMode: "Off"    # recommendation only — don't auto-apply
  resourcePolicy:
    containerPolicies:
      - containerName: anthra-api
        minAllowed:
          cpu: 50m
          memory: 64Mi
        maxAllowed:
          cpu: 2
          memory: 1Gi
        controlledResources: ["cpu", "memory"]
EOF

# VPA takes time to gather data — check recommendations after load test
kubectl get vpa anthra-api-vpa -n anthra
```

---

## PHASE 6 — Resource Tagging for Cost Attribution

**Why**: Cost Explorer can't tell you which service costs what without tags.
Tags = cost visibility = cost accountability.
This is the FinOps practice companies pay consultants thousands for.

```bash
# Tag all existing resources
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=anthra-cloud" \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text | \
  xargs -I{} aws ec2 create-tags \
    --resources {} \
    --tags \
      Key=Project,Value=anthra-cloud \
      Key=Environment,Value=demo \
      Key=CostCenter,Value=platform-engineering \
      Key=Owner,Value=gp-copilot \
      Key=ManagedBy,Value=terraform

# Enable Cost Allocation Tags in AWS Billing
aws ce update-cost-allocation-tags-status \
  --cost-allocation-tags-status \
    TagKey=Project,Status=Active \
    TagKey=Environment,Status=Active \
    TagKey=CostCenter,Status=Active

# Create a budget alert — never get surprised
aws budgets create-budget \
  --account-id $AWS_ACCOUNT_ID \
  --budget '{
    "BudgetName": "anthra-cloud-session-budget",
    "BudgetLimit": {
      "Amount": "25",
      "Unit": "USD"
    },
    "BudgetType": "COST",
    "TimeUnit": "MONTHLY",
    "CostFilters": {
      "TagKeyValue": ["user:Project$anthra-cloud"]
    }
  }' \
  --notifications-with-subscribers '[
    {
      "Notification": {
        "NotificationType": "ACTUAL",
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": 80,
        "ThresholdType": "PERCENTAGE"
      },
      "Subscribers": [
        {
          "SubscriptionType": "EMAIL",
          "Address": "your-email@gmail.com"
        }
      ]
    }
  ]'
```

---

## PHASE 7 — Load Test to Generate Real Metrics

**Why**: Empty cluster shows nothing. Load it up, then screenshot
the HPA scaling, Karpenter provisioning, and CloudWatch metrics.
This is what makes the portfolio data real.

```bash
# Deploy a simple load generator
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: load-generator
  namespace: anthra
spec:
  containers:
    - name: load-gen
      image: busybox
      command: ["/bin/sh", "-c"]
      args:
        - |
          while true; do
            wget -q -O- http://anthra-api:8080/health 2>/dev/null || true
            sleep 0.1
          done
  restartPolicy: Never
EOF

# Watch HPA respond in real time — screenshot this
watch kubectl get hpa -n anthra

# Watch Karpenter provision nodes if needed
kubectl logs -n kube-system -l app.kubernetes.io/name=karpenter -f

# Watch pod scaling
watch kubectl get pods -n anthra

# After 5 minutes — capture metrics
echo "=== AFTER OPTIMIZATION — UNDER LOAD ==="
kubectl top nodes
kubectl top pods -n anthra

# Get VPA recommendations (after 10+ minutes of data)
kubectl describe vpa anthra-api-vpa -n anthra | grep -A20 "Recommendation"

# Stop load test
kubectl delete pod load-generator -n anthra

# Watch scale down (Karpenter consolidates after load drops)
watch kubectl get nodes
```

---

## PHASE 8 — Cost Optimization Evidence Collection

**Why**: This is the data that goes on your resume.
Real numbers from real AWS metrics.

```bash
# CloudWatch — actual vs provisioned
echo "=== COST OPTIMIZATION EVIDENCE ==="

# Node utilization after optimization
kubectl top nodes --no-headers | \
  awk 'BEGIN {print "OPTIMIZED NODE UTILIZATION:"} 
  {print "  " $1 ": CPU=" $3 " Memory=" $5}'

# HPA state — shows it works
kubectl get hpa anthra-api-hpa -n anthra \
  -o custom-columns=\
"NAME:.metadata.name,\
CURRENT:.status.currentReplicas,\
DESIRED:.status.desiredReplicas,\
MIN:.spec.minReplicas,\
MAX:.spec.maxReplicas,\
CPU:.status.currentMetrics[0].resource.current.averageUtilization"

# Karpenter node provisioning efficiency
kubectl get nodes \
  -l managed-by=karpenter \
  -o custom-columns=\
"NODE:.metadata.name,\
TYPE:.metadata.labels.node\.kubernetes\.io/instance-type,\
ARCH:.metadata.labels.kubernetes\.io/arch,\
CAPACITY:.metadata.labels.karpenter\.sh/capacity-type"

# VPA recommendations — what it would right-size to
kubectl describe vpa anthra-api-vpa -n anthra

# CloudWatch metrics query — actual CPU usage over session
aws cloudwatch get-metric-statistics \
  --namespace ContainerInsights \
  --metric-name pod_cpu_utilization \
  --dimensions \
    Name=ClusterName,Value=$CLUSTER_NAME \
    Name=Namespace,Value=anthra \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 300 \
  --statistics Average \
  --query 'sort_by(Datapoints, &Timestamp)[].[Timestamp,Average]' \
  --output table

# Estimated cost savings calculation
cat << 'CALC'
=== COST SAVINGS CALCULATION ===

BEFORE (typical over-provisioned cluster):
  2x m5.large nodes @ $0.096/hr = $0.192/hr = $140/month
  CPU utilization: ~15% (over-provisioned)
  Memory utilization: ~20% (over-provisioned)

AFTER (Karpenter + Graviton + Spot):
  Karpenter provisions t4g.medium (Graviton, Spot) @ ~$0.013/hr
  CPU utilization: ~70% (right-sized by HPA)
  Memory utilization: ~75% (right-sized by VPA recommendations)
  Estimated cost: ~$10-15/month for equivalent workload

SAVINGS: ~$125-130/month (~89% reduction for this workload)

NOTE: In real client engagement — run Kubecost for exact numbers
CALC
```

---

## PHASE 9 — Verification Screenshots Checklist

```bash
# Take ALL of these screenshots before tearing down

# 1. Karpenter node provisioning
kubectl get nodes -l managed-by=karpenter -o wide
# Screenshot: shows Graviton/Spot nodes provisioned automatically

# 2. HPA scaling in action
kubectl get hpa -n anthra
kubectl describe hpa anthra-api-hpa -n anthra
# Screenshot: shows current/desired replicas responding to load

# 3. VPA recommendations
kubectl describe vpa anthra-api-vpa -n anthra
# Screenshot: shows recommended vs actual resource requests

# 4. CloudWatch Container Insights dashboard
# Open in browser:
echo "https://${AWS_REGION}.console.aws.amazon.com/cloudwatch/home?region=${AWS_REGION}#container-insights:infrastructure/eks-cluster/${CLUSTER_NAME}"
# Screenshot: CPU and memory utilization graphs

# 5. Cost Explorer tags working
echo "https://us-east-1.console.aws.amazon.com/cost-management/home#/cost-explorer"
# Screenshot: Costs broken down by Project=anthra-cloud tag

# 6. Node consolidation (after load drops)
kubectl get nodes
# Screenshot: Karpenter terminated empty nodes automatically

# 7. Security still intact on optimized cluster
kubectl get networkpolicy -n anthra
kubectl get externalsecret -n anthra
kubectl get sa anthra-api -n anthra -o yaml | grep role-arn
# Screenshot: optimization didn't break security

# 8. Combined summary
kubectl get all -n anthra
# Screenshot: full picture of what's running
```

---

## PHASE 10 — TEAR DOWN

```bash
# Same as Session 1 tear down
eksctl delete cluster --name $CLUSTER_NAME --region $AWS_REGION

# Additional Session 2 cleanup
aws budgets delete-budget \
  --account-id $AWS_ACCOUNT_ID \
  --budget-name anthra-cloud-session-budget

# Verify
aws eks list-clusters
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=anthra-cloud" \
  --query 'Reservations[].Instances[].[InstanceId,State.Name]'
```

---

## Resume Bullets This Session Generates

```
• Implemented Karpenter autoscaler with Graviton (ARM) + Spot instance
  node pools — provisioning right-sized nodes automatically and
  terminating idle nodes within 30 seconds, reducing compute costs
  by an estimated 40-60% vs static on-demand x86 node groups

• Deployed HPA + VPA for all workloads — scaling pods based on
  actual CPU/memory utilization and generating right-sizing
  recommendations that address the industry-wide 80% container
  resource waste problem

• Implemented cost allocation tagging and AWS Budgets alerts —
  enabling per-service cost attribution and automated spend
  governance across the platform
```

*Last updated: March 2026 | Anthra-CLOUD Session 2 | Cost Optimization Layer*