/**
 * PIPELINE-E2E: Full vulnerability disclosure pipeline trace
 *
 * Traces: Upload SBOM → Scan (clean) → Inject CVE → Scan (vulnerable) → SLA → Alert
 *
 * This test runs in TWO phases because k6 cannot modify the database directly.
 * The CVE injection happens via SQL between phases, orchestrated by run-e2e.sh.
 *
 * Phase 1 (upload + baseline scan):
 *   T0  Health check
 *   T1  Upload SBOM with e2e-pipeline-lib@1.0.0
 *   T2  Initial scan → baseline count
 *
 *   → SQL injection happens here (run-e2e.sh inserts CVE + vulnerability record) ←
 *
 * Phase 2 (detect + SLA + alert):
 *   T3  Second scan → vulnerability detected
 *   T4  Verify CVE visible via GET /api/vulnerabilities
 *   T5  Wait for SLA deadline
 *   T6  Verify SLA deadline anchored to discovered_at (not time.Now())
 *   T7  Check alerts
 *
 * Run via:
 *   ./run-e2e.sh          # full orchestrated run
 *   k6 run pipeline-e2e.spec.js  # phase 1 only (no CVE injection)
 *
 * Environment:
 *   API_URL     - server URL (default: http://localhost:28080)
 *   JWT_SECRET  - JWT signing secret
 *   ORG_ID      - organization UUID
 *   E2E_PHASE   - "1" or "2" (default: "1")
 *   E2E_SBOM_ID - sbom_id from phase 1 (needed for phase 2)
 */
import http from 'k6/http';
import { check, group, sleep } from 'k6';
import encoding from 'k6/encoding';
import crypto from 'k6/crypto';
import { Trend } from 'k6/metrics';
import { BASE_URL, JWT_SECRET, ORG_ID } from './common/config.js';

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: { checks: ['rate>0.99'] },
};

// ── Custom timing metrics ──────────────────────────────────────────────────
const tUpload = new Trend('e2e_upload_ms', false);
const tScan1 = new Trend('e2e_scan1_ms', false);
const tInject = new Trend('e2e_inject_ms', false);
const tScan2 = new Trend('e2e_scan2_ms', false);
const tVerifyAPI = new Trend('e2e_verify_api_ms', false);
const tSLA = new Trend('e2e_sla_ms', false);
const tAlert = new Trend('e2e_alert_ms', false);
const tPipeline = new Trend('e2e_pipeline_total_ms', false);

// ── JWT generation (inline to avoid import issues in k6) ──────────────────
function base64url(str) {
  return encoding.b64encode(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateToken() {
  const header = JSON.stringify({ alg: 'HS256', typ: 'JWT' });
  const now = Math.floor(Date.now() / 1000);
  const payload = JSON.stringify({
    sub: 'e2e-pipeline-test',
    email: 'e2e@test.local',
    org_id: ORG_ID,
    org_slug: 'demo',
    roles: ['admin', 'compliance_officer'],
    iat: now,
    exp: now + 3600,
  });
  const h = base64url(header);
  const p = base64url(payload);
  const sigBytes = crypto.hmac('sha256', JWT_SECRET, `${h}.${p}`, 'binary');
  const sig = encoding.b64encode(sigBytes, 'raw').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${h}.${p}.${sig}`;
}

// ── Constants ──────────────────────────────────────────────────────────────
const CVE_ID = 'CVE-2026-E2E-PIPELINE';
const COMPONENT = 'e2e-pipeline-lib';
const VERSION = '1.0.0';
const PHASE = __ENV.E2E_PHASE || '1';
const SBOM_ID = __ENV.E2E_SBOM_ID || '';

// ── Helpers ────────────────────────────────────────────────────────────────

function authHeaders(token) {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Organization-ID': ORG_ID,
  };
}

function uploadSBOM(token) {
  const sbom = JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    metadata: { component: { name: 'e2e-pipeline-app', version: '1.0.0' } },
    components: [{
      type: 'library',
      name: COMPONENT,
      version: VERSION,
      purl: `pkg:generic/${COMPONENT}@${VERSION}`,
    }],
  });

  const boundary = '----E2EPipeline' + Date.now();
  const body =
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="file"; filename="e2e-pipeline.cdx.json"\r\n' +
    'Content-Type: application/json\r\n\r\n' +
    sbom + '\r\n' +
    '--' + boundary + '--\r\n';

  return http.post(`${BASE_URL}/api/sboms/upload`, body, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Organization-ID': ORG_ID,
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
    },
  });
}

function createScan(token, sbomId) {
  return http.post(`${BASE_URL}/api/scan`, JSON.stringify({ sbom_id: sbomId }), {
    headers: authHeaders(token),
  });
}

function waitForScan(token, scanId, timeoutS = 60) {
  const deadline = Date.now() + timeoutS * 1000;
  while (Date.now() < deadline) {
    const res = http.get(`${BASE_URL}/api/scans?limit=100`, { headers: authHeaders(token) });
    if (res.status === 200) {
      const body = JSON.parse(res.body);
      for (const scan of (body.data || [])) {
        const id = scan.id || scan.scan_id;
        if (id === scanId) {
          if (scan.status === 'completed' || scan.status === 'failed') {
            return scan;
          }
        }
      }
    }
    sleep(2);
  }
  return null;
}

function getVulnerabilityCount(token) {
  const res = http.get(`${BASE_URL}/api/vulnerabilities?limit=100`, { headers: authHeaders(token) });
  if (res.status !== 200) return -1;
  const body = JSON.parse(res.body);
  return body.count || 0;
}

function waitForSLA(token, cve, timeoutS = 60) {
  const deadline = Date.now() + timeoutS * 1000;
  while (Date.now() < deadline) {
    const res = http.get(`${BASE_URL}/api/compliance/sla`, { headers: authHeaders(token) });
    if (res.status === 200) {
      const body = JSON.parse(res.body);
      const data = body.data || [];
      for (const sla of data) {
        if (sla.cve === cve) {
          return sla;
        }
      }
    }
    sleep(3);
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════
//  Main test — runs the phase specified by E2E_PHASE env var
// ══════════════════════════════════════════════════════════════════════════
export default function () {
  const token = generateToken();
  const pipelineStart = Date.now();

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`  E2E PIPELINE TEST — Phase ${PHASE}`);
  console.log(`  Server:   ${BASE_URL}`);
  console.log(`  CVE:      ${CVE_ID} → ${COMPONENT}@${VERSION}`);
  console.log(`  Org:      ${ORG_ID}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  if (PHASE === '1') {
    runPhase1(token, pipelineStart);
  } else {
    runPhase2(token, pipelineStart);
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  PHASE 1: Upload SBOM + baseline scan
// ══════════════════════════════════════════════════════════════════════════
function runPhase1(token, pipelineStart) {

  // ── T0: Health check ──────────────────────────────────────────────────
  group('T0: Health check', () => {
    const t0 = Date.now();
    const healthRes = http.get(`${BASE_URL}/health`);
    check(healthRes, { 'GET /health → 200': (r) => r.status === 200 });
    console.log(`  [T0] Health: ${healthRes.status} (${Date.now() - t0}ms)`);
    console.log(`       Body: ${healthRes.body}`);

    const readyRes = http.get(`${BASE_URL}/readyz`);
    check(readyRes, { 'GET /readyz → 200': (r) => r.status === 200 });
    console.log(`       Ready: ${readyRes.body}`);
  });
  console.log('');

  // ── T1: Upload SBOM ───────────────────────────────────────────────────
  let sbomId = '';
  group('T1: Upload SBOM', () => {
    const t1 = Date.now();
    const res = uploadSBOM(token);
    tUpload.add(Date.now() - t1);

    check(res, {
      'upload → 201': (r) => r.status === 200 || r.status === 201,
    });

    const body = JSON.parse(res.body);
    sbomId = body.data ? body.data.id : body.id;

    console.log(`  [T1] POST /api/sboms/upload → ${res.status} (${Date.now() - t1}ms)`);
    console.log(`       SBOM ID: ${sbomId}`);
    console.log(`       Response: ${res.body.substring(0, 200)}`);
  });
  console.log('');

  // ── T2: Initial scan ─────────────────────────────────────────────────
  group('T2: Initial scan (baseline)', () => {
    const t2 = Date.now();
    const scanRes = createScan(token, sbomId);

    check(scanRes, {
      'scan → 200/202': (r) => r.status === 200 || r.status === 202 || r.status === 201,
    });

    const scanBody = JSON.parse(scanRes.body);
    const scanId = scanBody.data ? (scanBody.data.scan_id || scanBody.data.id) : (scanBody.scan_id || scanBody.id);
    console.log(`  [T2] POST /api/scan → ${scanRes.status} (${Date.now() - t2}ms)`);
    console.log(`       Scan ID: ${scanId}`);
    console.log(`       Response: ${scanRes.body.substring(0, 200)}`);

    // Wait for completion
    const scan = waitForScan(token, scanId, 60);
    const scanDur = Date.now() - t2;
    tScan1.add(scanDur);

    if (scan) {
      console.log(`       Status: ${scan.status}`);
      console.log(`       Vulns found: ${scan.vulnerabilities_found}`);
      console.log(`       Duration: ${scanDur}ms`);
    } else {
      console.log(`       ⚠ Scan did not complete within 60s`);
    }

    const baselineVulns = getVulnerabilityCount(token);
    console.log(`       Baseline vulnerability count: ${baselineVulns}`);
  });
  console.log('');

  // ── Output SBOM ID for phase 2 ───────────────────────────────────────
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`  Phase 1 complete. SBOM ID: ${sbomId}`);
  console.log('  Run SQL injection, then:');
  console.log(`    E2E_PHASE=2 E2E_SBOM_ID=${sbomId} k6 run pipeline-e2e.spec.js`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // Export for the orchestrator script
  __ENV.E2E_SBOM_ID = sbomId;
}

// ══════════════════════════════════════════════════════════════════════════
//  PHASE 2: Second scan + verify + SLA + alert
// ══════════════════════════════════════════════════════════════════════════
function runPhase2(token, pipelineStart) {
  const sbomId = SBOM_ID;
  if (!sbomId) {
    console.error('  ERROR: E2E_SBOM_ID not set. Run phase 1 first.');
    return;
  }

  console.log(`  Using SBOM ID from phase 1: ${sbomId}`);
  console.log('');

  // ── T3: Second scan (post-CVE injection) ────────────────────────────
  let scan2Id = '';
  group('T3: Second scan (post-CVE injection)', () => {
    const t3 = Date.now();
    const scanRes = createScan(token, sbomId);

    check(scanRes, {
      'scan → 200/202': (r) => r.status === 200 || r.status === 202 || r.status === 201,
    });

    const scanBody = JSON.parse(scanRes.body);
    scan2Id = scanBody.data ? (scanBody.data.scan_id || scanBody.data.id) : (scanBody.scan_id || scanBody.id);

    console.log(`  [T3] POST /api/scan → ${scanRes.status} (${Date.now() - t3}ms)`);
    console.log(`       Scan ID: ${scan2Id}`);
    console.log(`       Response: ${scanRes.body.substring(0, 200)}`);

    // Wait for completion
    const scan = waitForScan(token, scan2Id, 60);
    const scanDur = Date.now() - t3;
    tScan2.add(scanDur);

    if (scan) {
      console.log(`       Status: ${scan.status}`);
      console.log(`       Vulns found: ${scan.vulnerabilities_found}`);
      console.log(`       Duration: ${scanDur}ms`);
    }
  });
  console.log('');

  // ── T4: Verify vulnerability via API ─────────────────────────────────
  group('T4: Verify vulnerability via API', () => {
    const t4 = Date.now();
    const res = http.get(`${BASE_URL}/api/vulnerabilities?limit=100`, { headers: authHeaders(token) });

    check(res, { 'GET /api/vulnerabilities → 200': (r) => r.status === 200 });

    const body = JSON.parse(res.body);
    const vulns = body.data || [];
    let found = false;

    for (const v of vulns) {
      if (v.cve === CVE_ID) {
        found = true;
        console.log(`  [T4] ✓ CVE found via GET /api/vulnerabilities:`);
        console.log(`       cve:           ${v.cve}`);
        console.log(`       severity:      ${v.severity}`);
        console.log(`       exploited:     ${v.exploited_in_wild}`);
        console.log(`       cvss:          ${v.cvss_score}`);
        console.log(`       discovered_at: ${v.discovered_at}`);

        check(null, {
          'CVE severity is critical': () => v.severity === 'critical',
          'CVE is exploited': () => v.exploited_in_wild === true,
          'CVE cvss ~9.8': () => Math.abs(v.cvss_score - 9.8) < 0.2,
        });
        break;
      }
    }

    check(null, { 'CVE appears in API': () => found });
    console.log(`       Total vulnerabilities: ${body.count}`);
    console.log(`       Duration: ${Date.now() - t4}ms`);

    tVerifyAPI.add(Date.now() - t4);
  });
  console.log('');

  // ── T5: Wait for SLA deadline ────────────────────────────────────────
  group('T5: Wait for SLA deadline calculation', () => {
    const t5 = Date.now();
    const sla = waitForSLA(token, CVE_ID, 60);

    if (sla) {
      console.log(`  [T5] ✓ SLA entry found:`);
      console.log(`       cve:             ${sla.cve}`);
      console.log(`       deadline:        ${sla.deadline}`);
      console.log(`       status:          ${sla.status}`);
      console.log(`       hours_remaining: ${sla.hours_remaining}`);

      // Verify SLA deadline is anchored to discovered_at
      // The CVE was discovered 2h ago, so deadline should be discovered_at + 24h (KEV)
      // i.e. deadline should be ~22h from now, NOT ~24h from now
      const deadlineTime = new Date(sla.deadline).getTime();
      const nowTime = Date.now();
      const hoursUntilDeadline = (deadlineTime - nowTime) / (1000 * 60 * 60);

      console.log(`       hours from now:  ${hoursUntilDeadline.toFixed(1)}h`);
      console.log(`       (expected ~22h if discovered 2h ago with 24h KEV SLA)`);

      // If discovered_at was 2h ago, and SLA is 24h from discovered_at,
      // then hours_remaining should be ~22h, not ~24h
      check(null, {
        'SLA hours_remaining ~22h (not ~24h from now)': () => {
          // Allow 1h tolerance for test timing
          return Math.abs(sla.hours_remaining - 22) < 1.5;
        },
        'SLA status is pending or violated': () =>
          sla.status === 'pending' || sla.status === 'violated',
      });

      tSLA.add(Date.now() - t5);
    } else {
      console.log(`  [T5] ⚠ SLA entry not found within 60s`);
      check(null, { 'SLA entry found': () => false });
    }
  });
  console.log('');

  // ── T6: Check alerts ─────────────────────────────────────────────────
  group('T6: Check alerts', () => {
    const t6 = Date.now();
    const res = http.get(`${BASE_URL}/api/alerts`, { headers: authHeaders(token) });

    console.log(`  [T6] GET /api/alerts → ${res.status}`);
    if (res.body && res.body.length > 2) {
      console.log(`       Body: ${res.body.substring(0, 300)}`);
    }

    check(res, { 'GET /api/alerts → 200': (r) => r.status === 200 });
    tAlert.add(Date.now() - t6);
  });
  console.log('');

  // ── T7: Final scan list (evidence) ──────────────────────────────────
  group('T7: Final scan list', () => {
    const res = http.get(`${BASE_URL}/api/scans?limit=10`, { headers: authHeaders(token) });
    check(res, { 'GET /api/scans → 200': (r) => r.status === 200 });

    const body = JSON.parse(res.body);
    console.log(`  [T7] Scans: ${body.total} total`);
    for (const scan of (body.data || []).slice(0, 5)) {
      const id = scan.id || scan.scan_id;
      console.log(`       ${id}: status=${scan.status} vulns=${scan.vulnerabilities_found} sbom=${scan.sbom_id}`);
    }
  });
  console.log('');

  // ── Summary ───────────────────────────────────────────────────────────
  const totalMs = Date.now() - pipelineStart;
  tPipeline.add(totalMs);

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  PHASE 2 COMPLETE');
  console.log(`  Total pipeline time: ${totalMs}ms`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}
