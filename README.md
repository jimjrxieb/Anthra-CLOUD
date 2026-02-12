# Anthra Security Platform — AWS Cloud Deployment

**Application:** Anthra Security Platform (Log Aggregation SaaS)
**Deployment:** AWS EKS Production Environment
**Objective:** Demonstrate AWS Solutions Architect Associate knowledge

---

## Project Overview

This is the **same Anthra application** from the FedRAMP engagement (slot-3), but deployed to AWS as a production-grade cloud architecture. This deployment showcases AWS Solutions Architect skills including:

- ✅ EKS cluster design and configuration
- ✅ Multi-AZ high availability architecture
- ✅ AWS Secrets Manager integration
- ✅ IAM roles for service accounts (IRSA)
- ✅ Application Load Balancer with SSL/TLS
- ✅ CloudWatch logging and monitoring
- ✅ VPC networking and security groups
- ✅ RDS PostgreSQL (Multi-AZ)
- ✅ ElastiCache Redis for sessions
- ✅ S3 for log archival
- ✅ Route53 DNS and ACM certificates

**Related Project:**
- **Slot-3 (Anthra-FedRAMP):** Same app, focus on FedRAMP compliance with GuidePoint
- **Slot-2 (Anthra-CLOUD):** Same app, focus on AWS architecture and deployment

---

## About Anthra

Anthra Security is a cloud-native security monitoring and log aggregation SaaS platform, founded in 2020. Multi-tenant platform for centralized security monitoring.

**Tech Stack:**
- **Frontend:** React 18 + Vite
- **API:** Python FastAPI
- **Log Ingest:** Go microservices
- **Database:** PostgreSQL (RDS Multi-AZ)
- **Cache:** Redis (ElastiCache)
- **Storage:** S3 (log archival)
- **Infrastructure:** EKS, ALB, Route53, Secrets Manager

---

## AWS Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AWS CLOUD ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Route53 (anthra.cloud)                                            │
│         │                                                            │
│         ▼                                                            │
│   ACM Certificate (*.anthra.cloud)                                  │
│         │                                                            │
│         ▼                                                            │
│   Application Load Balancer (us-east-1a, us-east-1b)                │
│         │                                                            │
│         ▼                                                            │
│   ┌─────────────────────────────────────────────────────────┐       │
│   │                      EKS CLUSTER                         │       │
│   │   ┌────────────────────────────────────────────────┐     │       │
│   │   │  Worker Nodes (t3.large, 3-6 nodes, Multi-AZ)│     │       │
│   │   │  ┌──────────┐  ┌──────────┐  ┌──────────┐    │     │       │
│   │   │  │ UI Pods  │  │ API Pods │  │Log Ingest│    │     │       │
│   │   │  └────┬─────┘  └────┬─────┘  └────┬─────┘    │     │       │
│   │   └───────┼─────────────┼─────────────┼──────────┘     │       │
│   │           │             │             │                 │       │
│   │           │     ┌───────▼─────────────▼──────┐          │       │
│   │           │     │  IAM Roles for Service     │          │       │
│   │           │     │  Accounts (IRSA)           │          │       │
│   │           │     └───────┬────────────────────┘          │       │
│   └───────────┼─────────────┼──────────────────────────────┘       │
│               │             │                                       │
│               ▼             ▼                                       │
│   ┌──────────────┐   ┌──────────────┐                              │
│   │ ElastiCache  │   │ RDS Postgres │                              │
│   │ Redis        │   │ (Multi-AZ)   │                              │
│   │ (sessions)   │   │ Primary +    │                              │
│   └──────────────┘   │ Standby      │                              │
│                      └──────┬───────┘                               │
│                             │                                       │
│                      ┌──────▼───────┐                               │
│                      │ AWS Secrets  │                               │
│                      │ Manager      │                               │
│                      └──────────────┘                               │
│                                                                      │
│   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐           │
│   │ CloudWatch   │   │ S3 Bucket    │   │ CloudTrail   │           │
│   │ Logs         │   │ (log archive)│   │ (audit)      │           │
│   └──────────────┘   └──────────────┘   └──────────────┘           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## AWS Components

### Compute (EKS)
- **Cluster:** EKS 1.28+ in `us-east-1`
- **Node Group:** `t3.large`, 3-6 nodes (autoscaling), Multi-AZ
- **IRSA:** IAM roles for pods (S3, Secrets Manager, CloudWatch)
- **CNI:** AWS VPC CNI for pod networking

### Networking (VPC)
- **VPC:** `10.0.0.0/16`
- **Public Subnets:** `10.0.1.0/24`, `10.0.2.0/24` (ALB, NAT Gateway)
- **Private Subnets:** `10.0.10.0/24`, `10.0.11.0/24` (EKS workers)
- **Database Subnets:** `10.0.20.0/24`, `10.0.21.0/24` (RDS)
- **NAT Gateway:** Multi-AZ for egress
- **Security Groups:**
  - ALB → EKS (port 80/443)
  - EKS → RDS (port 5432)
  - EKS → ElastiCache (port 6379)

### Load Balancing (ALB)
- **Type:** Application Load Balancer
- **Listeners:**
  - HTTP (80) → HTTPS redirect
  - HTTPS (443) → EKS Ingress Controller
- **Target Groups:** EKS NodePort services
- **Health Checks:** `/api/health`
- **SSL:** ACM certificate for `*.anthra.cloud`

### Database (RDS)
- **Engine:** PostgreSQL 15
- **Instance:** `db.t3.medium` (Multi-AZ)
- **Storage:** 100GB gp3 (encrypted)
- **Backups:** Automated daily snapshots (7-day retention)
- **Parameter Group:** Custom (optimized for EKS workloads)

### Caching (ElastiCache)
- **Engine:** Redis 7.x
- **Node:** `cache.t3.medium` (Multi-AZ)
- **Replication:** Primary + Read Replica
- **Use Case:** Session management, rate limiting

### Secrets (Secrets Manager)
- **Secrets:**
  - `anthra/db-credentials` (RDS connection)
  - `anthra/api-keys` (internal service auth)
  - `anthra/redis-password` (ElastiCache)
- **Rotation:** Automated 90-day rotation
- **Access:** IRSA-based (no hardcoded credentials)

### Storage (S3)
- **Bucket:** `anthra-logs-archive-{account-id}`
- **Purpose:** Long-term log storage (compliance)
- **Lifecycle:**
  - Standard → IA (30 days)
  - IA → Glacier (90 days)
- **Encryption:** S3-SSE (server-side)

### DNS (Route53)
- **Hosted Zone:** `anthra.cloud`
- **Records:**
  - `anthra.cloud` → ALB (A record)
  - `api.anthra.cloud` → ALB (CNAME)
  - `*.anthra.cloud` → Wildcard ACM cert

### Monitoring (CloudWatch)
- **Logs:** EKS control plane, worker nodes, application logs
- **Metrics:** Custom metrics (API latency, log ingest rate)
- **Alarms:**
  - EKS node CPU > 80%
  - RDS connection pool exhaustion
  - ALB 5xx error rate > 1%
- **Dashboards:** Real-time cluster health

### Audit (CloudTrail)
- **Trail:** Organization-wide trail
- **Logs:** S3 bucket (encrypted)
- **Purpose:** Security audit, compliance

---

## Deployment Guide

### Prerequisites

```bash
# AWS CLI configured
aws configure

# kubectl installed
# eksctl installed
# helm installed
```

### 1. Deploy Infrastructure (Terraform)

```bash
cd infrastructure/terraform

# Initialize
terraform init

# Plan
terraform plan -var="environment=production"

# Apply
terraform apply -var="environment=production"

# Outputs: EKS cluster name, ALB DNS, RDS endpoint
```

### 2. Configure kubectl

```bash
# Update kubeconfig
aws eks update-kubeconfig --name anthra-production --region us-east-1

# Verify
kubectl get nodes
```

### 3. Deploy Application (Helm)

```bash
cd ../../charts/anthra

# Install with production values
helm install anthra . \
  --namespace anthra \
  --create-namespace \
  --values values-production.yaml

# Verify
kubectl get pods -n anthra
```

### 4. Configure DNS

```bash
# Get ALB DNS
kubectl get ingress -n anthra

# Update Route53 (or via Terraform)
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch file://route53-changes.json
```

### 5. Test Deployment

```bash
# Health check
curl https://api.anthra.cloud/api/health

# Send test log
curl -X POST https://api.anthra.cloud/ingest \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "test", "level": "INFO", "message": "Hello AWS"}'
```

---

## AWS Solutions Architect Skills Demonstrated

### Compute
- ✅ EKS cluster design (control plane + data plane)
- ✅ EC2 Auto Scaling Groups for worker nodes
- ✅ IAM Roles for Service Accounts (IRSA)
- ✅ Pod Security Standards (PSS)

### Networking
- ✅ VPC design (public/private/database subnets)
- ✅ Multi-AZ for high availability
- ✅ NAT Gateway for egress
- ✅ Security Groups (least privilege)
- ✅ Network ACLs

### Load Balancing
- ✅ Application Load Balancer (ALB)
- ✅ SSL/TLS termination with ACM
- ✅ Health checks and target groups
- ✅ ALB Ingress Controller for K8s

### Database
- ✅ RDS Multi-AZ deployment
- ✅ Automated backups and snapshots
- ✅ Encryption at rest and in transit
- ✅ Parameter groups and option groups

### Caching
- ✅ ElastiCache Redis for sessions
- ✅ Multi-AZ replication
- ✅ Connection pooling

### Security
- ✅ AWS Secrets Manager integration
- ✅ IAM least privilege (IRSA)
- ✅ Encryption everywhere (TLS, S3-SSE, RDS encryption)
- ✅ CloudTrail audit logging
- ✅ VPC security groups

### Monitoring
- ✅ CloudWatch Logs (centralized logging)
- ✅ CloudWatch Metrics (custom application metrics)
- ✅ CloudWatch Alarms (operational alerts)
- ✅ CloudWatch Dashboards

### DNS
- ✅ Route53 hosted zone
- ✅ A/CNAME records
- ✅ ACM certificate for SSL

### Storage
- ✅ S3 for log archival
- ✅ Lifecycle policies (Standard → IA → Glacier)
- ✅ Server-side encryption

### Cost Optimization
- ✅ Right-sized instances (t3.large for nodes, db.t3.medium for RDS)
- ✅ Auto Scaling (scale workers based on load)
- ✅ S3 lifecycle policies (reduce storage costs)
- ✅ ElastiCache read replicas (reduce RDS load)

---

## Directory Structure

```
Anthra-CLOUD/
├── README.md                    # This file (AWS focus)
├── infrastructure/
│   ├── terraform/               # Infrastructure as Code
│   │   ├── vpc.tf
│   │   ├── eks.tf
│   │   ├── rds.tf
│   │   ├── elasticache.tf
│   │   ├── alb.tf
│   │   ├── route53.tf
│   │   └── secrets-manager.tf
│   └── kubernetes/              # K8s manifests
│       ├── namespace.yaml
│       ├── api-deployment.yaml
│       ├── secrets-external.yaml  # ExternalSecrets Operator
│       └── ingress-alb.yaml
├── charts/anthra/               # Helm chart
│   ├── Chart.yaml
│   ├── values.yaml
│   └── values-production.yaml
├── api/                         # Application code (same as FedRAMP)
├── services/
├── ui/
└── docs/
    ├── AWS-ARCHITECTURE.md      # Detailed AWS design
    ├── DEPLOYMENT-GUIDE.md      # Step-by-step deployment
    └── COST-ESTIMATION.md       # AWS cost breakdown
```

---

## Cost Estimation (Monthly)

| Service | Configuration | Cost/Month |
|---------|--------------|------------|
| **EKS Control Plane** | 1 cluster | $73 |
| **EC2 Worker Nodes** | 3x t3.large (24x7) | $225 |
| **RDS PostgreSQL** | db.t3.medium Multi-AZ | $120 |
| **ElastiCache Redis** | cache.t3.medium | $50 |
| **ALB** | 1 ALB + data transfer | $25 |
| **NAT Gateway** | 2 NAT (Multi-AZ) | $90 |
| **S3** | 500GB storage + requests | $15 |
| **CloudWatch** | Logs + metrics | $30 |
| **Route53** | 1 hosted zone | $0.50 |
| **Secrets Manager** | 3 secrets | $1.20 |
| **Data Transfer** | 1TB/month egress | $90 |
| **Total** | | **~$720/month** |

**Cost optimization opportunities:**
- Use Spot instances for worker nodes (50% savings)
- Reserved Instances for RDS (40% savings)
- Savings Plans for EKS nodes (30% savings)

---

## Differences from FedRAMP Deployment

| Aspect | FedRAMP (Slot-3) | AWS Cloud (Slot-2) |
|--------|------------------|-------------------|
| **Focus** | Compliance (NIST 800-53) | Cloud Architecture |
| **Deployment** | Local + K8s hardening | AWS EKS Production |
| **Secrets** | Env vars (gap to fix) | AWS Secrets Manager |
| **Database** | Local PostgreSQL | RDS Multi-AZ |
| **Caching** | None | ElastiCache Redis |
| **Networking** | docker-compose | VPC, ALB, Multi-AZ |
| **Monitoring** | Logs only | CloudWatch full stack |
| **DNS** | localhost | Route53 + ACM |
| **Storage** | Local disk | S3 with lifecycle |
| **Purpose** | Show GuidePoint methodology | Show AWS SA skills |

---

## AWS Certifications Alignment

This project directly aligns with **AWS Solutions Architect Associate (SAA-C03)** exam domains:

1. **Design Secure Architectures (30%)**
   - IAM roles, Security Groups, Secrets Manager, encryption

2. **Design Resilient Architectures (26%)**
   - Multi-AZ, Auto Scaling, ALB, RDS standby

3. **Design High-Performing Architectures (24%)**
   - ElastiCache, ALB, EKS node optimization, S3 lifecycle

4. **Design Cost-Optimized Architectures (20%)**
   - Right-sizing, Auto Scaling, S3 tiers, Reserved Instances

---

## Next Steps

1. **Deploy to AWS:** Use Terraform to provision infrastructure
2. **Harden Security:** Apply security best practices (already done in FedRAMP slot-3)
3. **Add Observability:** Prometheus/Grafana on top of CloudWatch
4. **Implement CI/CD:** GitHub Actions → ECR → EKS rolling updates
5. **Cost Optimize:** Analyze with AWS Cost Explorer, implement Savings Plans

---

## Related Projects

- **Slot-3 (Anthra-FedRAMP):** GuidePoint FedRAMP compliance engagement
- **Slot-2 (Anthra-CLOUD):** AWS production deployment (this project)

Same application, different objectives. Together they demonstrate both compliance expertise and cloud architecture skills.

---

*Production-ready AWS architecture for a modern SaaS platform.*
