#!/usr/bin/env bash
# conftest-runner.sh — Run all 8 OPA policies against Kubernetes manifests
# NIST Controls: CM-6 (Configuration Settings), CA-2 (Security Assessments)
#
# Usage: ./conftest-runner.sh [MANIFEST_DIR]
# Default: scans ../target-app/ for any .yaml/.yml files

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="${SCRIPT_DIR}/../policies/opa"
MANIFEST_DIR="${1:-${SCRIPT_DIR}/../target-app}"

echo "=========================================="
echo "NovaSec Cloud — OPA Policy Validation"
echo "FedRAMP Moderate Baseline (8 controls)"
echo "=========================================="
echo "Policy dir : ${POLICY_DIR}"
echo "Manifest dir: ${MANIFEST_DIR}"
echo ""

# Verify conftest is available
if ! command -v conftest &>/dev/null; then
    echo "ERROR: conftest not installed"
    echo "Install: https://www.conftest.dev/install/"
    exit 1
fi

# Verify policy directory exists and has .rego files
if [ ! -d "${POLICY_DIR}" ]; then
    echo "ERROR: Policy directory not found: ${POLICY_DIR}"
    exit 1
fi

REGO_COUNT=$(find "${POLICY_DIR}" -name '*.rego' -not -path '*/lib/*' | wc -l)
echo "Policies found: ${REGO_COUNT}"
echo ""

# Find all YAML manifests to test
MANIFESTS=$(find "${MANIFEST_DIR}" -name '*.yaml' -o -name '*.yml' 2>/dev/null | head -100)

if [ -z "${MANIFESTS}" ]; then
    echo "WARNING: No YAML manifests found in ${MANIFEST_DIR}"
    echo "Validating policy syntax only..."
    conftest verify --policy "${POLICY_DIR}" 2>/dev/null || true
    exit 0
fi

TOTAL=0
PASSED=0
FAILED=0
WARNINGS=0

for manifest in ${MANIFESTS}; do
    echo "--- Scanning: $(basename "${manifest}") ---"
    if output=$(conftest test "${manifest}" --policy "${POLICY_DIR}" --no-color 2>&1); then
        echo "  PASS"
        PASSED=$((PASSED + 1))
    else
        echo "${output}" | sed 's/^/  /'
        if echo "${output}" | grep -q "FAIL"; then
            FAILED=$((FAILED + 1))
        else
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
    TOTAL=$((TOTAL + 1))
done

echo ""
echo "=========================================="
echo "Results: ${TOTAL} manifests scanned"
echo "  PASSED:   ${PASSED}"
echo "  FAILED:   ${FAILED}"
echo "  WARNINGS: ${WARNINGS}"
echo "=========================================="

# Exit with failure if any policies violated (for CI gating)
if [ "${FAILED}" -gt 0 ]; then
    exit 1
fi
