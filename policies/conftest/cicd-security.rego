package cicd.security

# UNDERSTANDING: CI/CD pipeline = Production deployment authority
# Compromised pipeline = Supply chain attack (SolarWinds, CodeCov patterns)
# Each gate prevents specific attack vectors
#
# INPUT: CI/CD pipeline configuration JSON (NOT Kubernetes manifests)
# This policy only fires when the input contains pipeline/CI fields.

import future.keywords.contains
import future.keywords.if
import future.keywords.in

metadata := {
    "policy": "cicd-pipeline-security",
    "version": "1.1.0",
    "compliance": ["SLSA-Level-4", "NIST-SSDF", "SOC2-CC7.2"],
    "supply_chain": "software-supply-chain-security",
    "last_review": "2026-02-26"
}

# --- Guard: only evaluate when input is a CI/CD pipeline config ---
is_pipeline_input {
    input.pipeline
}

is_pipeline_input {
    input.security_scans
}

is_pipeline_input {
    input.container.image_scan
}

# Pipeline Execution Controls

# CRITICAL: Branch protection enforcement
# THREAT: Unauthorized code deployment, backdoors
# COMPLIANCE: SLSA Build L3, SOC2 CC8.1
deny[msg] {
    is_pipeline_input
    input.pipeline.branch == "main"
    not input.pipeline.pull_request.approved
    msg := "Direct commits to main branch prohibited - require PR approval"
}

deny[msg] {
    is_pipeline_input
    input.pipeline.branch in ["main", "master", "production"]
    count(input.pipeline.pull_request.approvers) < 2
    msg := "Production branches require minimum 2 approvals"
}

# CRITICAL: Code signing verification
# THREAT: Tampered commits, impersonation
# COMPLIANCE: SLSA Source L3
deny[msg] {
    is_pipeline_input
    input.pipeline.commits[_].signature_verified == false
    msg := sprintf("Commit '%s' not GPG signed - require signed commits", [input.pipeline.commits[_].sha])
}

# Build Security

# CRITICAL: Dependency vulnerability scanning
# THREAT: Known CVEs, vulnerable dependencies
# COMPLIANCE: NIST SSDF, SLSA Build L2
deny[msg] {
    is_pipeline_input
    not input.security_scans.dependency_check.executed
    msg := "Dependency vulnerability scan required before build"
}

deny[msg] {
    is_pipeline_input
    input.security_scans.dependency_check.executed
    vuln := input.security_scans.dependency_check.vulnerabilities[_]
    vuln.severity in ["CRITICAL", "HIGH"]
    msg := sprintf("Critical/High vulnerability found: %s in %s",
                   [vuln.cve, vuln["package"]])
}

# HIGH: SAST (Static Analysis) enforcement
# THREAT: Code-level vulnerabilities, injection flaws
# COMPLIANCE: NIST SSDF PS.1, SOC2 CC8.1
deny[msg] {
    is_pipeline_input
    not input.security_scans.sast.executed
    msg := "SAST scan required - security vulnerabilities must be detected pre-deployment"
}

deny[msg] {
    is_pipeline_input
    input.security_scans.sast.executed
    finding := input.security_scans.sast.findings[_]
    finding.severity == "HIGH"
    not finding.false_positive
    msg := sprintf("SAST High severity finding: %s at %s:%d",
                   [finding.rule, finding.file, finding.line])
}

# HIGH: Secret scanning enforcement
# THREAT: Credential exposure, API key leaks
# COMPLIANCE: NIST SSDF RV.1
deny[msg] {
    is_pipeline_input
    not input.security_scans.secret_scan.executed
    msg := "Secret scanning required - prevent credential exposure"
}

deny[msg] {
    is_pipeline_input
    input.security_scans.secret_scan.secrets_found > 0
    msg := sprintf("Found %d secrets in code - remove before deployment",
                   [input.security_scans.secret_scan.secrets_found])
}

# Container Security

# CRITICAL: Container image scanning
# THREAT: Vulnerable base images, malware
# COMPLIANCE: SLSA Build L3, NIST RV.1
deny[msg] {
    is_pipeline_input
    not input.container.image_scan.executed
    msg := "Container image vulnerability scan required"
}

deny[msg] {
    is_pipeline_input
    input.container.image_scan.executed
    input.container.image_scan.critical_vulnerabilities > 0
    msg := sprintf("Container has %d critical vulnerabilities - fix before deployment",
                   [input.container.image_scan.critical_vulnerabilities])
}

# HIGH: Image signature requirement
# THREAT: Tampered images, supply chain attacks
# COMPLIANCE: SLSA Build L4
deny[msg] {
    is_pipeline_input
    not input.container.image_signed
    is_production_deployment
    msg := "Production images must be signed with Cosign/Notary"
}

# HIGH: Base image restrictions
# THREAT: Untrusted base images, supply chain risk
deny[msg] {
    is_pipeline_input
    not is_approved_base_image(input.container.base_image)
    msg := sprintf("Base image '%s' not in approved list", [input.container.base_image])
}

approved_base_images := [
    "gcr.io/distroless/",
    "company-registry/approved/",
    "chainguard/"
]

is_approved_base_image(image) {
    startswith(image, approved_base_images[_])
}

# Deployment Gates

# CRITICAL: Environment-specific requirements
# THREAT: Dev credentials in prod, data leakage
# COMPLIANCE: SOC2 CC6.6, PCI-DSS 6.4.1
deny[msg] {
    is_pipeline_input
    is_production_deployment
    not input.deployment.reviewed_by_security
    msg := "Production deployments require security team review"
}

deny[msg] {
    is_pipeline_input
    is_production_deployment
    not has_rollback_plan
    msg := "Production deployments require documented rollback plan"
}

has_rollback_plan {
    input.deployment.rollback_plan.documented == true
    input.deployment.rollback_plan.tested == true
}

# HIGH: Test coverage enforcement
# THREAT: Untested code, runtime failures
# COMPLIANCE: NIST SSDF PW.8
deny[msg] {
    is_pipeline_input
    input.tests.coverage_percent < 80
    is_production_deployment
    msg := sprintf("Test coverage %d%% below required 80%% for production",
                   [input.tests.coverage_percent])
}

# MEDIUM: Integration test requirement
# COMPLIANCE: NIST SSDF PW.8
deny[msg] {
    is_pipeline_input
    not input.tests.integration_tests.executed
    is_production_deployment
    msg := "Integration tests required for production deployment"
}

# Artifact Management

# HIGH: Artifact provenance
# THREAT: Supply chain attacks, artifact tampering
# COMPLIANCE: SLSA Provenance L3
deny[msg] {
    is_pipeline_input
    not input.artifact.provenance.generated
    is_production_deployment
    msg := "Production artifacts require SLSA provenance attestation"
}

deny[msg] {
    is_pipeline_input
    input.artifact.provenance.generated
    not input.artifact.provenance.verified
    msg := "Artifact provenance verification failed"
}

# HIGH: Artifact storage security
# THREAT: Unauthorized access, tampering
deny[msg] {
    is_pipeline_input
    not input.artifact.storage.encrypted
    msg := "Artifact storage must be encrypted at rest"
}

deny[msg] {
    is_pipeline_input
    not input.artifact.storage.access_logged
    msg := "Artifact access must be logged for audit trail"
}

# Secrets Management in Pipeline

# CRITICAL: No secrets in pipeline logs
# THREAT: Credential exposure in logs
# COMPLIANCE: CIS Docker 5.25
deny[msg] {
    is_pipeline_input
    log_line := input.pipeline.logs[_]
    contains_secret_pattern(log_line)
    msg := "Pipeline logs contain potential secret - enable secret masking"
}

contains_secret_pattern(text) {
    # AWS access key pattern
    regex.match(`AKIA[0-9A-Z]{16}`, text)
}

contains_secret_pattern(text) {
    # Generic API key pattern
    regex.match(`[aA][pP][iI]_?[kK][eE][yY].*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}`, text)
}

# HIGH: Environment variable security
# THREAT: Secret exposure via env vars
deny[msg] {
    is_pipeline_input
    env := input.pipeline.environment_variables[_]
    env.value  # Has explicit value, not reference
    is_secret_name(env.name)
    msg := sprintf("Secret '%s' hardcoded in pipeline - use secret manager", [env.name])
}

is_secret_name(name) {
    lower(name) in [
        "password", "api_key", "secret", "token",
        "access_key", "private_key", "secret_key"
    ]
}

# Compliance & Audit

# MEDIUM: Pipeline audit logging
# COMPLIANCE: SOC2 CC7.2, PCI-DSS 10.2
deny[msg] {
    is_pipeline_input
    not input.pipeline.audit_log_enabled
    msg := "Pipeline audit logging must be enabled"
}

# MEDIUM: Change tracking
# COMPLIANCE: SOC2 CC8.1, ISO27001 A.12.1.2
deny[msg] {
    is_pipeline_input
    is_production_deployment
    not input.deployment.change_ticket
    msg := "Production deployments require change management ticket"
}

# LOW: Documentation requirements
warn[msg] {
    is_pipeline_input
    is_production_deployment
    not input.deployment.documentation.updated
    msg := "Deployment documentation should be updated"
}

# Helper Functions

is_production_deployment {
    input.deployment.environment in ["production", "prod", "live"]
}

is_production_deployment {
    input.deployment.namespace == "production"
}
