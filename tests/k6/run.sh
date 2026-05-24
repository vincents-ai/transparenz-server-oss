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
export JWT_SECRET="${JWT_SECRET:-test-jwt-secret-for-playwright-minimum-32-characters}"
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

# Commercial-only specs

# If a specific spec is provided, run only that
if [[ $# -gt 0 ]]; then
  SPECS=("$@")
else
