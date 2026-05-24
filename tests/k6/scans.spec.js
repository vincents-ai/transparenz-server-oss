/**
 * K6-SCAN: Scan lifecycle contract tests (8 tests)
 *
 * Verifies: create scan, list scans, status enums, vulnerability linkage.
 */
import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { BASE_URL } from './common/config.js';
import { generateToken, isUUID, assertSchema, seedSBOM, cleanSBOM } from './common/helpers.js';

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: { checks: ['rate>0.99'] },
};

const VALID_STATUSES = ['pending', 'in_progress', 'completed', 'failed', 'done'];

export default function () {
  const token = generateToken();
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Organization-ID': '00000000-0000-0000-0000-000000000001',
  };

  // Seed an SBOM to scan
  const sbom = seedSBOM(token, 'k6-scan-test');
  const sbomId = sbom.id;

  // ─── SCAN-1: Create scan ──────────────────────────────────────────
  group('SCAN-1: Create scan', () => {
    const res = http.post(`${BASE_URL}/api/scan`, JSON.stringify({ sbom_id: sbomId }), { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 202/200': (r) => r.status === 202 || r.status === 200 || r.status === 201,
      'id is UUID': () => isUUID(body.id || body.scan_id),
      'status is pending/in_progress': () => (body.status === 'pending' || body.status === 'in_progress'),
    });
  });

  // ─── SCAN-2: Scan rejects missing sbom_id ────────────────────────
  group('SCAN-2: Scan rejects missing sbom_id', () => {
    const res = http.post(`${BASE_URL}/api/scan`, JSON.stringify({}), { headers });
    check(res, {
      'status 400': (r) => r.status === 400,
    });
  });

  // ─── SCAN-3: Scan rejects invalid sbom_id ────────────────────────
  group('SCAN-3: Scan rejects non-existent sbom_id', () => {
    const res = http.post(`${BASE_URL}/api/scan`, JSON.stringify({ sbom_id: '00000000-0000-0000-0000-999999999999' }), { headers });
    check(res, {
      'status 404': (r) => r.status === 404,
    });
  });

  // ─── SCAN-4: List scans ──────────────────────────────────────────
  group('SCAN-4: List scans', () => {
    const res = http.get(`${BASE_URL}/api/scans`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'paginated': () => {
        const errs = assertSchema(body, { data: 'array', total: 'number', limit: 'number', offset: 'number' });
        return errs.length === 0;
      },
    });
  });

  // ─── SCAN-5: Scan has required fields ─────────────────────────────
  group('SCAN-5: Scan has required fields', () => {
    const res = http.get(`${BASE_URL}/api/scans`, { headers });
    const body = JSON.parse(res.body);

    if (body.data && body.data.length > 0) {
      const scan = body.data[0];
      const errs = assertSchema(scan, {
        id: 'uuid', status: 'string', created_at: 'iso8601',
      });
      // Also accept scan_id if id is missing
      if (errs.length > 0 && scan.scan_id) {
        scan.id = scan.scan_id;
        const retry = assertSchema(scan, { id: 'uuid', status: 'string', created_at: 'iso8601' });
        check(null, { 'scan has required fields': () => retry.length === 0 });
        return;
      }
      check(null, {
        'scan has required fields': () => errs.length === 0,
      });
    }
  });

  // ─── SCAN-6: Scan status enum ─────────────────────────────────────
  group('SCAN-6: Scan status enum valid', () => {
    const res = http.get(`${BASE_URL}/api/scans`, { headers });
    const body = JSON.parse(res.body);

    if (body.data && body.data.length > 0) {
      check(null, {
        'all statuses are valid enum values': () =>
          body.data.every(s => VALID_STATUSES.includes(s.status)),
      });
    }
  });

  // ─── SCAN-7: Get scan vulnerabilities ────────────────────────────
  group('SCAN-7: Get scan vulnerabilities', () => {
    // Find a completed scan
    const listRes = http.get(`${BASE_URL}/api/scans`, { headers });
    const listBody = JSON.parse(listRes.body);
    const completedScan = (listBody.data || []).find(s => s.status === 'completed');

    if (completedScan) {
      const res = http.get(`${BASE_URL}/api/scans/${completedScan.id}/vulnerabilities`, { headers });
      check(res, {
        'status 200': (r) => r.status === 200,
        'response has data field': (r) => {
          try { const b = JSON.parse(r.body); return b.data !== undefined || b.count !== undefined; } catch { return false; }
        },
      });
    }
  });

  // ─── SCAN-8: Vulnerabilities link to known CVEs ───────────────────
  group('SCAN-8: Vulnerabilities have CVE identifiers', () => {
    const listRes = http.get(`${BASE_URL}/api/scans`, { headers });
    const listBody = JSON.parse(listRes.body);
    const completedScan = (listBody.data || []).find(s => s.status === 'completed');

    if (completedScan) {
      const res = http.get(`${BASE_URL}/api/scans/${completedScan.id}/vulnerabilities`, { headers });
      const body = JSON.parse(res.body);
      const vulns = body.data || body;

      if (Array.isArray(vulns) && vulns.length > 0) {
        check(null, {
          'each vuln has cve field': () => vulns.every(v => typeof v.cve === 'string' && v.cve.startsWith('CVE-')),
        });
      }
    }
  });

  // Cleanup
  cleanSBOM(token, sbomId);
}
