#!/usr/bin/env bash
# Test K8s manifests against OPA conftest policies.
# Mirrors the CI gate — run locally before pushing.
#
# Usage:
#   bash scripts/test-policies.sh              # test all manifests
#   bash scripts/test-policies.sh --warn-only  # warnings only (no hard fail)

set -euo pipefail

POLICIES="policies/conftest"
WARN_FLAG=""

if [[ "${1:-}" == "--warn-only" ]]; then
  WARN_FLAG="--fail-on-warn=false"
fi

if ! command -v conftest &>/dev/null; then
  echo "conftest not installed: https://www.conftest.dev/install/"
  exit 1
fi

MANIFESTS=(
  infrastructure/anthra-api/base/*.yaml
  infrastructure/anthra-ui/base/*.yaml
  infrastructure/anthra-log-ingest/base/*.yaml
  infrastructure/anthra-db/base/*.yaml
  infrastructure/*.yaml
)

echo "=== Conftest Policy Gate (local) ==="
echo "Policies: ${POLICIES}/"
echo ""

conftest test "${MANIFESTS[@]}" \
  --policy "$POLICIES" \
  --all-namespaces \
  --output stdout \
  $WARN_FLAG

echo ""
echo "=== All policies passed ==="
