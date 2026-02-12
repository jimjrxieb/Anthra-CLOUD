# Anthra Security Inc. — Company Profile

**Founded:** 2020
**Headquarters:** Austin, TX
**Employees:** 25
**Funding:** Series A ($8M, led by Kleiner Perkins)
**Website:** anthra.io (fictional)

---

## Mission

Democratize enterprise-grade security monitoring for modern cloud-native organizations.

---

## Company Story

### The Problem (2019)

Traditional SIEM platforms (Splunk, LogRhythm, QRadar) cost $200K-$1M+ annually and require dedicated security teams to operate. Startups and SMBs building on Kubernetes had no affordable option for centralized security monitoring.

### The Solution (2020)

Anthra launched as a cloud-native alternative:
- **Kubernetes-first design** (agent deployed as DaemonSet)
- **Pay-as-you-go pricing** ($99/month base + $0.10/GB ingested)
- **Pre-built integrations** (AWS CloudTrail, GCP Audit Logs, GitHub Actions)
- **Compliance dashboards** (SOC2, PCI-DSS, GDPR)

### Growth (2020-2025)

- **Year 1:** 20 customers, $150K ARR
- **Year 2:** 60 customers, $800K ARR, Series A funding
- **Year 3:** 150 customers, $3.2M ARR
- **Year 4:** Expanding to mid-market (250-500 employees)
- **Current:** Targeting federal market (requires FedRAMP)

---

## Product: Anthra Platform

Multi-tenant SaaS security monitoring platform.

### Core Features

| Feature | Description | Market Positioning |
|---------|-------------|--------------------|
| **Log Aggregation** | Centralized collection from agents | "Like Splunk, but 10x cheaper" |
| **Threat Detection** | ML-powered anomaly detection | "Datadog Security without the markup" |
| **Compliance Reporting** | SOC2, PCI, GDPR dashboards | "Built-in compliance, not bolt-on" |
| **Multi-Tenant Isolation** | K8s namespace per customer | "Enterprise security for SMB pricing" |

### Tech Stack

- **Frontend:** React 18 + Vite
- **API:** Python FastAPI
- **Ingest:** Go microservices (high-throughput log collection)
- **Data:** PostgreSQL + Elasticsearch (optional)
- **Infrastructure:** EKS (AWS), multi-region
- **CI/CD:** GitHub Actions
- **Monitoring:** Prometheus + Grafana

### Why This Stack?

**Speed over security** (initially):
- MD5 for passwords (fast to implement)
- No auth middleware (ship features faster)
- Secrets in env vars (avoid AWS Secrets Manager complexity)
- Root containers (default Docker behavior)
- No NetworkPolicy (Kubernetes doesn't require it)

"We were a 4-person team racing to Series A. We built for velocity, not compliance."

---

## Customer Base

### Commercial Segment (Current)

**Target:** Series A-C startups, 50-500 employees

**Industries:**
- FinTech (Stripe competitors, neobanks)
- DevOps/SaaS (monitoring tools, CI/CD platforms)
- Cybersecurity vendors (SecOps tools)

**Notable Customers** (fictional):
- Acme Payments (fintech, 150 employees)
- CloudBuild (CI/CD SaaS, 80 employees)
- SecureOps (SOC automation, 120 employees)

### Federal Segment (Target)

**Goal:** Win federal contracts requiring FedRAMP Moderate

**Target Agencies:**
- **Department of Homeland Security (DHS)** — CISA needs SOC monitoring
- **Veterans Affairs (VA)** — Modernizing security operations
- **General Services Administration (GSA)** — Cross-agency log aggregation
- **Department of Defense (DoD IL4)** — Eventually (requires FedRAMP High)

**Contract Value:** $2M-$5M per agency (3-year contracts)

**Why Federal?:**
- Recurring revenue (multi-year contracts)
- Expansion opportunity (25+ civilian agencies)
- Competitive moat (FedRAMP barrier to entry)

---

## The FedRAMP Challenge

### Why We Need Help

Our engineering team (12 developers) focused on:
- ✅ Feature velocity
- ✅ Customer acquisition
- ✅ Product-market fit

We didn't focus on:
- ❌ Security-first architecture
- ❌ NIST 800-53 compliance
- ❌ Federal procurement requirements

**The gap:** Our CTO (Sarah Chen, ex-Docker) knows Kubernetes. She doesn't know FedRAMP.

### Enter GuidePoint Security

**Why GuidePoint:**
1. **Federal expertise** — Done this 50+ times for SaaS vendors
2. **Automation** — Iron Legion platform (JSA agents) automates 70% of remediation
3. **Timeline** — 10 weeks to ATO-ready vs. 12-18 months DIY
4. **Cost** — $250K engagement vs. $500K+ hiring federal compliance consultants

**Engagement scope:**
- Gap assessment (NIST 800-53 mapping)
- Policy implementation (Kyverno, Gatekeeper, Falco)
- K8s hardening (security contexts, RBAC, NetworkPolicy)
- CI/CD integration (Trivy, Semgrep, Gitleaks)
- Documentation generation (SSP, POA&M, SAR)
- Evidence automation (continuous compliance)

---

## Team

| Role | Name | Background |
|------|------|------------|
| **CEO** | Mike Rodriguez | Ex-Palo Alto Networks, GTM leader |
| **CTO** | Sarah Chen | Ex-Docker, Kubernetes contributor |
| **VP Engineering** | David Park | Ex-Datadog, led log ingestion team |
| **Lead DevSec** | Priya Sharma | OSCP, building security features |
| **Federal BD** | John Williams | Ex-Lockheed, pursuing FedRAMP deals |

---

## Financials

| Metric | Value |
|--------|-------|
| **ARR** | $3.2M (150 customers) |
| **Burn Rate** | $180K/month |
| **Runway** | 44 months (post Series A) |
| **ACV** | $21K/customer (commercial) |
| **Target Federal ACV** | $200K-$500K/agency |
| **Break-Even** | $8M ARR (projected 18 months) |

### FedRAMP ROI

**Investment:**
- GuidePoint engagement: $250K
- Engineering time: 2 FTEs for 3 months (~$100K)
- **Total cost:** $350K

**Projected Return:**
- First federal contract: $2M (3 years) = $667K/year
- 3 agencies by year-end: $6M (3 years) = $2M/year
- **ROI:** 5.7x in year 1

---

## Why We'll Win Federal

1. **Modern stack** — Agencies want cloud-native, not legacy SIEM
2. **Cost advantage** — 80% cheaper than Splunk/QRadar
3. **K8s expertise** — DoD/CISA are all-in on Kubernetes
4. **Speed** — Deploy in weeks, not months (vs. traditional SIEM)
5. **GuidePoint backing** — Federal buyers trust GuidePoint's work

---

## Current State Before GuidePoint

**Application:** Feature-complete, scales well, solid product
**Security:** Built by devs, not security architects
**Compliance:** Zero FedRAMP readiness

**Our ask to GuidePoint:**
"Make us FedRAMP Moderate compliant without rewriting the entire application."

---

*This document is part of the GuidePoint Security engagement materials.*
*Engagement methodology: GP-CONSULTING/07-FedRAMP-Ready/*
