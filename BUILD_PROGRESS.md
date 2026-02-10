# FedRAMP Repo Build Progress

> This file tracks restructuring progress. If a terminal session dies, resume from the next incomplete step.

## Status Legend
- [x] Complete
- [ ] Not started
- [~] In progress

## Step 1: Git Remote Update [x]
- [x] Renamed `origin` → `upstream` (DVWA)
- [x] Set new `origin` → `https://github.com/jimjrxieb/FedRAMP.git`
- [x] Removed `secured` remote
- [x] Renamed branch `master` → `main`

## Step 2: Move DVWA into target-app/ [x]
- [x] `git mv` all PHP files to `target-app/`
- [x] `git mv` config/assets (robots.txt, security.txt, favicon.ico, php.ini, compose.yml, Dockerfile)
- [x] `git mv` directories (config/, database/, dvwa/, external/, hackable/, vulnerabilities/, docs/, tests/)
- [x] `git mv` CHANGELOG.md, SECURITY.md, multilingual READMEs
- [x] Renamed README.md → target-app/DVWA-README.md
- [x] Renamed COPYING.txt → LICENSE
- [x] Created target-app/README.md

## Step 3: Reorganize Evidence [x]
- [x] Created evidence/scan-reports/ and evidence/remediation/
- [x] Moved scan_initial.json → evidence/scan-reports/initial-scan.json
- [x] Moved scan_semgrep.json → evidence/scan-reports/semgrep-scan.json
- [x] Moved scan_trivy.json → evidence/scan-reports/trivy-scan.json
- [x] Moved scan_verification.json → evidence/scan-reports/verification-scan.json
- [x] Moved JADE_SECURITY_REPORT.md → evidence/scan-reports/jade-security-report.md
- [x] Moved GP-Copilot/README.md → evidence/scan-reports/README.md
- [x] Moved SECURITY_REMEDIATION.md → evidence/remediation/SECURITY_REMEDIATION.md
- [x] Removed empty GP-Copilot/ directory

## Step 4: Create FedRAMP Compliance Structure [~]
- [x] Created compliance/ssp/README.md
- [x] Created compliance/ssp/system-description.md
- [x] Created compliance/ssp/authorization-boundary.md
- [ ] Create compliance/ssp/ssp-skeleton.md
- [ ] Create compliance/control-families/README.md
- [ ] Create compliance/control-families/AC-access-control.md
- [ ] Create compliance/control-families/AU-audit.md
- [ ] Create compliance/control-families/CA-assessment.md
- [ ] Create compliance/control-families/CM-config-mgmt.md
- [ ] Create compliance/control-families/IA-identification.md
- [ ] Create compliance/control-families/RA-risk-assessment.md
- [ ] Create compliance/control-families/SC-system-comms.md
- [ ] Create compliance/control-families/SI-system-integrity.md
- [ ] Create compliance/poam/poam-template.md
- [ ] Create compliance/poam/poam-dvwa-findings.md
- [ ] Create compliance/sar/sar-template.md
- [ ] Create compliance/control-matrix.md

## Step 5: Create Automation Configs [ ]
- [ ] Create automation/scanning/trivy-config.yaml
- [ ] Create automation/scanning/semgrep-rules.yaml
- [ ] Create automation/scanning/gitleaks.toml
- [ ] Create automation/scanning/scan-and-map.py
- [ ] Create automation/policies/conftest/fedramp-controls.rego
- [ ] Create automation/policies/kyverno/ (3-5 policies)
- [ ] Create automation/policies/gatekeeper/ (constraint templates)
- [ ] Create automation/remediation/ (5 templates)
- [ ] Create automation/kubernetes/ (namespace, networkpolicy, deployment, service, rbac)

## Step 6: Create Demo Walkthrough [ ]
- [ ] Create demo/README.md
- [ ] Create demo/01-target-app-overview.md
- [ ] Create demo/02-pre-deployment-scan.md
- [ ] Create demo/03-finding-classification.md
- [ ] Create demo/04-nist-control-mapping.md
- [ ] Create demo/05-automated-remediation.md
- [ ] Create demo/06-compliance-evidence.md
- [ ] Create demo/07-continuous-monitoring.md
- [ ] Create demo/diagrams/iron-legion-fedramp.md

## Step 7: GitHub Actions [ ]
- [ ] Remove vulnerable.yml
- [ ] Create sast-analysis.yml (replaces codeql + shiftleft)
- [ ] Create container-scan.yml (replaces docker-image.yml)
- [ ] Update pytest.yml (fix paths to target-app/tests/)
- [ ] Create fedramp-compliance.yml
- [ ] Create policy-check.yml
- [ ] Update all branch references: master → main

## Step 8: Root-Level Files [ ]
- [ ] Create README.md
- [ ] Create ARCHITECTURE.md
- [ ] Create root compose.yml
- [ ] Update .gitignore
- [ ] Update .dockerignore

## Step 9: Push [ ]
- [ ] Push main to origin (jimjrxieb/FedRAMP.git)

## Reference Files
- Build plan: `/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/jsa/fedramobuildplan.md`
- NovaPay Federal scenario (fictional client for portfolio framing)
- Parent project compliance mappings: `GP-BEDROCK-AGENTS/jsa-infrasec/knowledge/compliance_mappings.py`
- Parent project policy templates: `GP-BEDROCK-AGENTS/jsa-infrasec/knowledge/policy-templates/`
- Parent project remediation templates: `GP-BEDROCK-AGENTS/jsa-infrasec/knowledge/remediation-templates/`
