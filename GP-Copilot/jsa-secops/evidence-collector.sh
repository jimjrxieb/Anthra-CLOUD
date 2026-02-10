#!/usr/bin/env bash
# evidence-collector.sh — Aggregate evidence artifacts for FedRAMP 3PAO review
# NIST Controls: CA-2 (Security Assessments), AU-6 (Audit Review)
#
# Collects scan reports, policy validation results, audit logs, and runtime
# alerts into a timestamped evidence package.
#
# Usage: ./evidence-collector.sh [--output-dir DIR]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEDRAMP_DIR="${SCRIPT_DIR}/.."
OUTPUT_DIR="${1:-${FEDRAMP_DIR}/evidence}"
TIMESTAMP=$(date -u +"%Y%m%d-%H%M%SZ")
EVIDENCE_DIR="${OUTPUT_DIR}/${TIMESTAMP}"

echo "=========================================="
echo "NovaSec Cloud — Evidence Collector"
echo "FedRAMP Moderate | 3PAO Ready"
echo "=========================================="
echo "Output: ${EVIDENCE_DIR}"
echo ""

mkdir -p "${EVIDENCE_DIR}"/{scan-reports,policy-results,audit-logs,runtime-alerts}

# 1. Collect scan reports (from jsa-secops scan-and-map)
echo "[1/5] Collecting scan reports..."
if [ -d "${FEDRAMP_DIR}/evidence/scan-reports" ]; then
    cp -r "${FEDRAMP_DIR}/evidence/scan-reports/"*.json "${EVIDENCE_DIR}/scan-reports/" 2>/dev/null || echo "  No scan reports found"
else
    echo "  No previous scan reports — run scan-and-map.py first"
fi

# 2. Run conftest against policies (live validation)
echo "[2/5] Running policy validation..."
if command -v conftest &>/dev/null; then
    conftest test "${FEDRAMP_DIR}/policies/opa/" --policy "${FEDRAMP_DIR}/policies/opa/" \
        --output json > "${EVIDENCE_DIR}/policy-results/opa-validation.json" 2>&1 || true
    echo "  OPA policy validation complete"
else
    echo "  conftest not installed — skipping policy validation"
fi

# 3. Collect Kyverno policy audit results (if kubectl available)
echo "[3/5] Collecting admission control evidence..."
if command -v kubectl &>/dev/null; then
    kubectl get policyreport -A -o json > "${EVIDENCE_DIR}/policy-results/kyverno-reports.json" 2>/dev/null || echo "  No Kyverno reports available"
    kubectl get constrainttemplates -o json > "${EVIDENCE_DIR}/policy-results/gatekeeper-templates.json" 2>/dev/null || echo "  No Gatekeeper templates available"
else
    echo "  kubectl not available — skipping cluster evidence"
fi

# 4. Collect Falco alerts (if log files exist)
echo "[4/5] Collecting runtime alerts..."
if [ -d "/var/log/falco" ]; then
    cp /var/log/falco/falco_output.json "${EVIDENCE_DIR}/runtime-alerts/" 2>/dev/null || echo "  No Falco logs found"
else
    echo "  No Falco logs directory — skipping runtime alerts"
fi

# 5. Generate evidence manifest
echo "[5/5] Generating evidence manifest..."
cat > "${EVIDENCE_DIR}/MANIFEST.json" << EOF
{
    "evidence_package": "NovaSec Cloud FedRAMP Moderate",
    "collected_at": "${TIMESTAMP}",
    "collected_by": "GP-Copilot Iron Legion — JSA-SecOps",
    "baseline": "FedRAMP Moderate Rev 5",
    "priority_controls": ["AC-2", "AC-6", "AU-2", "CM-6", "SC-7", "SC-8", "SI-2", "SI-4"],
    "artifacts": {
        "scan_reports": "scan-reports/",
        "policy_results": "policy-results/",
        "audit_logs": "audit-logs/",
        "runtime_alerts": "runtime-alerts/"
    },
    "iron_legion_agents": {
        "jsa-devsec": "Pre-deployment scanning (Trivy, Semgrep, Gitleaks, Conftest)",
        "jsa-infrasec": "Runtime enforcement (Falco, NetworkPolicy, pod isolation)",
        "jsa-secops": "Compliance reporting (scan-and-map, evidence collection)"
    }
}
EOF

echo ""
echo "=========================================="
echo "Evidence package: ${EVIDENCE_DIR}"
ARTIFACT_COUNT=$(find "${EVIDENCE_DIR}" -type f | wc -l)
echo "Artifacts collected: ${ARTIFACT_COUNT}"
echo "=========================================="
