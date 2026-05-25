#!/usr/bin/env bash
# =============================================================================
# E2E Pipeline Test Orchestrator
#
# Runs the full vulnerability disclosure pipeline:
#   Phase 1: k6 uploads SBOM + runs baseline scan
#   SQL:      Inject CVE into feed + vulnerability table
#   Phase 2: k6 runs second scan + verifies SLA + alerts
#
# All HTTP traces, timings, and DB state are captured.
#
# Usage:
#   ./tests/k6/run-e2e.sh
#   API_URL=http://other:8080 ./tests/k6/run-e2e.sh
#
# Requires: k6, psql, a running transparenz-server
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Configuration ────────────────────────────────────────────────────────────
export API_URL="${API_URL:-http://localhost:28080}"
export JWT_SECRET="${JWT_SECRET:-my-test-secret-key-at-least-32-chars}"
export ORG_ID="${ORG_ID:-00000000-0000-0000-0000-000000000001}"
export DB_URL="${DB_URL:-postgres://test:test@localhost:25432/transparenz?sslmode=disable}"

CVE_ID="CVE-2026-E2E-PIPELINE"
COMPONENT="e2e-pipeline-lib"
VERSION="1.0.0"
SEVERITY="critical"
CVSS="9.8"

# Discovered 2 hours ago — tests SLA deadline anchoring
DISCOVERED_AT=$(date -u -d '2 hours ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
                date -u -v-2H '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
                echo "")

# ── Colors ──────────────────────────────────────────────────────────────────
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  E2E PIPELINE: SBOM Clean → Vulnerable → Alerted${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Server:      $API_URL"
echo "  DB:          $DB_URL"
echo "  CVE:         $CVE_ID → ${COMPONENT}@${VERSION}"
echo "  Severity:    $SEVERITY (CVSS $CVSS)"
echo "  Discovered:  $DISCOVERED_AT (2h ago)"
echo "  JWT secret:  ${JWT_SECRET:0:10}…"
echo ""

# ── Verify prerequisites ───────────────────────────────────────────────────
echo -e "${YELLOW}→${NC} Checking prerequisites…"

if ! command -v k6 &>/dev/null; then
    echo "ERROR: k6 not found. Install with: nix-shell -p k6"
    exit 1
fi

curl -sf "$API_URL/health" >/dev/null 2>&1 || {
    echo "ERROR: Server not reachable at $API_URL"
    exit 1
}
echo -e "  ${GREEN}✓${NC} Server is healthy"

psql "$DB_URL" -c "SELECT 1" >/dev/null 2>&1 || {
    echo "ERROR: Cannot connect to DB at $DB_URL"
    exit 1
}
echo -e "  ${GREEN}✓${NC} DB is reachable"
echo ""

# ── Clean up from any previous run ──────────────────────────────────────────
echo -e "${YELLOW}→${NC} Cleaning up previous E2E data…"
psql "$DB_URL" >/dev/null 2>&1 <<SQL
DELETE FROM compliance.sla_tracking WHERE cve LIKE 'CVE-2026-E2E%';
DELETE FROM compliance.scan_vulnerabilities WHERE scan_id IN (
    SELECT s.id FROM compliance.scans s
    JOIN compliance.sbom_uploads u ON s.sbom_id = u.id
    WHERE u.filename LIKE 'e2e-pipeline%'
);
DELETE FROM compliance.scans WHERE sbom_id IN (
    SELECT id FROM compliance.sbom_uploads WHERE filename LIKE 'e2e-pipeline%'
);
DELETE FROM compliance.vulnerabilities WHERE cve LIKE 'CVE-2026-E2E%';
DELETE FROM compliance.vulnerability_feeds WHERE cve LIKE 'CVE-2026-E2E%';
DELETE FROM compliance.sbom_uploads WHERE filename LIKE 'e2e-pipeline%';
SQL
echo -e "  ${GREEN}✓${NC} DB cleaned"
echo ""

E2E_START=$(date +%s%N)

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1: Upload SBOM + baseline scan
# ═════════════════════════════════════════════════════════════════════════════
echo -e "${CYAN}━━━ PHASE 1: Upload SBOM + baseline scan ━━━${NC}"
PHASE1_START=$(date +%s%N)

E2E_PHASE=1 k6 run --no-thresholds "$SCRIPT_DIR/pipeline-e2e.spec.js" 2>&1 | tee /tmp/e2e-phase1.log
PHASE1_EXIT=$?

PHASE1_END=$(date +%s%N)
PHASE1_MS=$(( (PHASE1_END - PHASE1_START) / 1000000 ))

if [ $PHASE1_EXIT -ne 0 ]; then
    echo "ERROR: Phase 1 failed (exit $PHASE1_EXIT)"
    exit 1
fi

# Extract SBOM ID from phase 1 output
SBOM_ID=$(grep "SBOM ID:" /tmp/e2e-phase1.log | head -1 | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')

if [ -z "$SBOM_ID" ]; then
    echo "ERROR: Could not extract SBOM ID from phase 1 output"
    cat /tmp/e2e-phase1.log
    exit 1
fi

echo ""
echo -e "  ${GREEN}✓${NC} Phase 1 complete (${PHASE1_MS}ms)"
echo -e "  SBOM ID: $SBOM_ID"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
#  SQL INJECTION: Insert CVE into feed + vulnerability table
# ═════════════════════════════════════════════════════════════════════════════
echo -e "${CYAN}━━━ Injecting CVE into feed ━━━${NC}"
INJECT_START=$(date +%s%N)

psql "$DB_URL" >/dev/null 2>&1 <<SQL
-- Insert into vulnerability_feeds (simulates VulnzSyncService.SyncAll)
INSERT INTO compliance.vulnerability_feeds
    (id, cve, kev_exploited, enisa_severity, affected_products, last_synced_at, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    '${CVE_ID}',
    true,
    '${SEVERITY}',
    '[{"name":"${COMPONENT}","vendor":"e2e-test","version":"${VERSION}"}]'::jsonb,
    NOW(), NOW(), NOW()
)
ON CONFLICT (cve) DO UPDATE SET
    kev_exploited = true,
    enisa_severity = '${SEVERITY}',
    affected_products = '[{"name":"${COMPONENT}","vendor":"e2e-test","version":"${VERSION}"}]'::jsonb,
    last_synced_at = NOW(),
    updated_at = NOW();

-- Insert into vulnerabilities (simulates ScanWorker detection)
INSERT INTO compliance.vulnerabilities
    (id, org_id, cve, severity, cvss_score, exploited_in_wild, discovered_at, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    '${ORG_ID}',
    '${CVE_ID}',
    '${SEVERITY}',
    ${CVSS},
    true,
    NOW() - INTERVAL '2 hours',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;
SQL

INJECT_END=$(date +%s%N)
INJECT_MS=$(( (INJECT_END - INJECT_START) / 1000000 ))

echo -e "  ${GREEN}✓${NC} CVE injected (${INJECT_MS}ms)"
echo "  $CVE_ID: severity=$SEVERITY exploited=true discovered=$DISCOVERED_AT"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2: Second scan + verify + SLA + alert
# ═════════════════════════════════════════════════════════════════════════════
echo -e "${CYAN}━━━ PHASE 2: Scan → Verify → SLA → Alert ━━━${NC}"
PHASE2_START=$(date +%s%N)

E2E_PHASE=2 E2E_SBOM_ID="$SBOM_ID" k6 run --no-thresholds "$SCRIPT_DIR/pipeline-e2e.spec.js" 2>&1 | tee /tmp/e2e-phase2.log
PHASE2_EXIT=$?

PHASE2_END=$(date +%s%N)
PHASE2_MS=$(( (PHASE2_END - PHASE2_START) / 1000000 ))

if [ $PHASE2_EXIT -ne 0 ]; then
    echo "ERROR: Phase 2 failed (exit $PHASE2_EXIT)"
    exit 1
fi

echo ""
echo -e "  ${GREEN}✓${NC} Phase 2 complete (${PHASE2_MS}ms)"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
#  FINAL DB STATE VERIFICATION
# ═════════════════════════════════════════════════════════════════════════════
echo -e "${CYAN}━━━ Final DB state ━━━${NC}"

echo ""
echo "  Vulnerabilities:"
psql "$DB_URL" -c "SELECT cve, severity, exploited_in_wild, discovered_at, created_at FROM compliance.vulnerabilities WHERE cve LIKE 'CVE-2026-E2E%' ORDER BY cve;" 2>/dev/null

echo ""
echo "  SLA tracking:"
psql "$DB_URL" -c "SELECT cve, status, deadline, EXTRACT(EPOCH FROM (deadline - discovered_at))/3600 AS sla_window_hours FROM compliance.sla_tracking JOIN compliance.vulnerabilities USING (cve) WHERE cve LIKE 'CVE-2026-E2E%';" 2>/dev/null

echo ""
echo "  Scans:"
psql "$DB_URL" -c "SELECT s.id, s.status, s.vulnerabilities_found, u.filename FROM compliance.scans s JOIN compliance.sbom_uploads u ON s.sbom_id = u.id WHERE u.filename LIKE 'e2e-pipeline%' ORDER BY s.created_at;" 2>/dev/null

# ═════════════════════════════════════════════════════════════════════════════
#  TIMING SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
E2E_END=$(date +%s%N)
TOTAL_MS=$(( (E2E_END - E2E_START) / 1000000 ))
PIPELINE_MS=$(( (E2E_END - INJECT_START) / 1000000 ))

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  TIMING SUMMARY${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
printf "  %-30s %6dms\n" "Phase 1 (upload + scan):" "$PHASE1_MS"
printf "  %-30s %6dms\n" "CVE injection:" "$INJECT_MS"
printf "  %-30s %6dms\n" "Phase 2 (scan + verify):" "$PHASE2_MS"
echo "  ────────────────────────────────────────"
printf "  %-30s %6dms\n" "CVE inject → SLA set:" "$PIPELINE_MS"
printf "  %-30s %6dms\n" "Total E2E:" "$TOTAL_MS"
echo ""
echo "  SLA erosion analysis:"
echo "    Pipeline time: ${PIPELINE_MS}ms"
echo "    Critical (72h): $(( PIPELINE_MS * 100 / 259200000 ))% erosion"
echo "    KEV (24h):      $(( PIPELINE_MS * 100 / 86400000 ))% erosion"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "  Logs: /tmp/e2e-phase1.log /tmp/e2e-phase2.log"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
