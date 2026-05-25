#!/usr/bin/env bash
# Run k6 API contract tests for transparenz-server
#
# Usage:
#   ./tests/k6/run.sh              # Run all tests against localhost:28080
#   API_URL=http://other:8080 ./tests/k6/run.sh
#   ./tests/k6/run.sh sboms        # Run single spec
#
# Requires: k6 (nix-shell -p k6)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export API_URL="${API_URL:-http://localhost:28080}"
export JWT_SECRET="${JWT_SECRET:-my-test-secret-key-at-least-32-chars}"
export ORG_ID="${ORG_ID:-00000000-0000-0000-0000-000000000001}"

# Shared specs (OSS + Commercial)
SHARED_SPECS=(
  "system"
  "sboms"
  "scans"
  "vulnerabilities"
  "compliance"
  "disclosures"
  "vex"
  "enisa"
  "audit"
)

# If a specific spec is provided, run only that
if [[ $# -gt 0 ]]; then
  SPECS=("$@")
else
  SPECS=("${SHARED_SPECS[@]}")
fi

TOTAL=0
PASSED=0
FAILED=0

for spec in "${SPECS[@]}"; do
  FILE="${SCRIPT_DIR}/${spec}.spec.js"
  if [[ ! -f "$FILE" ]]; then
    echo "SKIP: ${spec} (file not found: ${FILE})"
    continue
  fi

  echo "━━━ ${spec} ━━━"
  if k6 run --no-thresholds --no-summary "$FILE" 2>&1; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
  fi
  TOTAL=$((TOTAL + 1))
  echo ""
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "k6 Results: ${PASSED}/${TOTAL} passed, ${FAILED} failed"
if [[ $FAILED -gt 0 ]]; then
  exit 1
fi
