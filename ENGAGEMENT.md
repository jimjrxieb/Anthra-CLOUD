# NovaPay Federal — Engagement Details

## Client Profile

**NovaPay Federal** is a fintech company that provides payroll and financial management services to state and local governments. They recently won a contract to manage payroll for a VA hospital system — their first federal engagement.

**The problem**: NovaPay can't start work without FedRAMP authorization. Their application was built with speed-to-market in mind, not compliance. There's no security documentation, no NIST control mapping, and no formal vulnerability management program. Their leadership estimated 12-18 months and $500K+ if done manually.

## The Application

NovaPay's platform runs on AWS EKS with a React frontend, Python API backend, PostgreSQL database, and S3 for document storage. CI/CD is GitHub Actions.

For this engagement, DVWA (Damn Vulnerable Web Application) serves as a simplified stand-in for NovaPay's application. It provides realistic vulnerabilities — SQL injection, XSS, command injection, hardcoded credentials — that map directly to the kinds of findings we'd encounter in a real-world assessment.

**Why DVWA?**: A real production app would contain proprietary code. DVWA is open-source and intentionally vulnerable, making it the perfect candidate for demonstrating the Iron Legion's scanning, classification, and remediation capabilities against realistic attack vectors.

## Technology Stack

| Component | Technology | FedRAMP Relevance |
|-----------|-----------|-------------------|
| **Application** | PHP 8 + Apache (DVWA) | Target of RA-5 vulnerability scanning |
| **Database** | MariaDB 10 | Data protection (SC-28) |
| **Container** | Docker | SI-2 image scanning |
| **Orchestration** | Kubernetes (EKS) | AC-6, CM-6, SC-7 policy enforcement |
| **CI/CD** | GitHub Actions | CA-7 continuous monitoring |
| **IaC** | Kubernetes manifests (Git-tracked) | CM-2 baseline configuration |

## Engagement Timeline

### Phase 1: Gap Assessment (Week 1-2)

We pointed the Iron Legion at NovaPay's codebase:

- **JSA-DevSec** ran Trivy, Semgrep, Gitleaks, and Conftest
- **JADE** classified 35 findings using the Iron Legion rank system
- **scan-and-map.py** mapped every finding to NIST 800-53 controls

**Findings breakdown**: 15 E-rank (auto-fix), 12 D-rank (auto-fix with logging), 5 C-rank (JADE-approved), 3 B-rank (human-reviewed).

### Phase 2: Control Implementation (Week 2-4)

- **E/D findings** (27): Auto-remediated by JSA agents — dependency upgrades, secret removal, config fixes. Zero human intervention required.
- **C findings** (5): JADE approved policy deployments — Kyverno admission policies, NetworkPolicy, audit logging configuration.
- **B findings** (3): Human reviewed architecture changes — credential management redesign, authentication flow hardening.
- **Policy deployment**: Kyverno ClusterPolicies + OPA Gatekeeper constraints + Conftest CI checks deployed to cluster.

### Phase 3: Documentation (Week 4-5)

Generated from templates with real scan data:
- **SSP** (System Security Plan) with 15 controls documented
- **8 Control Family documents** with evidence links
- **POA&M** tracking findings through closure
- **SAR** (Security Assessment Report) with methodology and results
- **Control Matrix** linking every control to tools, evidence, and rank

### Phase 4: Evidence Collection (Week 5-6)

- Scan artifacts (Trivy JSON, Semgrep JSON, Gitleaks JSON)
- NIST mapping report from scan-and-map.py
- Policy validation results from Conftest
- SBOM in CycloneDX format
- RBAC and NetworkPolicy state dumps
- Remediation before/after documentation

### Phase 5: 3PAO Preparation (Week 6)

- GitHub Actions workflows running on every push (continuous monitoring)
- Falco runtime detection deployed
- Kyverno admission enforcement active
- All 15 controls documented with linked evidence
- Zero open findings above D-rank
- Audit readiness checklist complete

## Outcome

NovaPay Federal went from zero compliance to audit-ready in 6 weeks. What would have taken 12-18 months of manual work was compressed into an automated, evidence-driven process.

Every finding is traceable: scanner → NIST control → evidence artifact → remediation → verification. The auditor doesn't need to trust us — they can verify every claim through the evidence chain.

---

*Engagement delivered using the GP-Copilot Iron Legion security platform — CKS | CKA | CCSP Certified Standards*
