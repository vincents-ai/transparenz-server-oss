/**
 * K6-DISC: Disclosure CRUD + SLA contract tests (10 tests)
 *
 * Verifies: create, get, list, status update, SLA compliance.
 * Key: values in GET must match values POSTed (database round-trip).
 */
import http from 'k6/http';
import { check, group } from 'k6';
import { BASE_URL } from './common/config.js';
import { generateToken, isUUID, assertSchema } from './common/helpers.js';

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: { checks: ['rate>0.99'] },
};

const VALID_STATUSES = ['received', 'triaging', 'acknowledged', 'fixing', 'fixed', 'disclosed', 'rejected', 'withdrawn'];

export default function () {
  const token = generateToken();
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Organization-ID': '00000000-0000-0000-0000-000000000001',
  };

  let disclosureId;
  const testCve = 'CVE-2026-9901';
  const testTitle = 'k6 contract test disclosure';
  const testSeverity = 'high';

  // ─── DISC-1: Create disclosure ────────────────────────────────────
  group('DISC-1: Create disclosure — returned values match input', () => {
    const payload = {
      cve: testCve,
      title: testTitle,
      description: 'k6 automated test description',
      severity: testSeverity,
      reporter_name: 'k6 Tester',
      reporter_email: 'k6@test.local',
      reporter_public: false,
    };

    const res = http.post(`${BASE_URL}/api/disclosures`, JSON.stringify(payload), { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200/201': (r) => r.status === 200 || r.status === 201,
      'cve matches input': () => body.cve === testCve,
      'title matches input': () => body.title === testTitle,
      'severity matches input': () => body.severity === testSeverity,
      'reporter_name matches': () => body.reporter_name === 'k6 Tester',
      'reporter_email matches': () => body.reporter_email === 'k6@test.local',
      'id is UUID': () => isUUID(body.id),
      'default status is received': () => body.status === 'received',
    });

    disclosureId = body.id;
  });

  // ─── DISC-2: Create rejects bad CVE ──────────────────────────────
  group('DISC-2: Create rejects invalid CVE', () => {
    const res = http.post(`${BASE_URL}/api/disclosures`, JSON.stringify({
      cve: 'INVALID', title: 'Test', severity: 'low',
    }), { headers });
    check(res, {
      'status 400': (r) => r.status === 400,
    });
  });

  // ─── DISC-3: Create rejects missing fields ───────────────────────
  group('DISC-3: Create rejects missing required fields', () => {
    const res = http.post(`${BASE_URL}/api/disclosures`, JSON.stringify({}), { headers });
    check(res, {
      'status 400': (r) => r.status === 400,
    });
  });

  // ─── DISC-4: List disclosures ────────────────────────────────────
  group('DISC-4: List disclosures', () => {
    const res = http.get(`${BASE_URL}/api/disclosures`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'paginated': () => Array.isArray(body.data || body),
    });
  });

  // ─── DISC-5: Get disclosure by ID — values match created ─────────
  group('DISC-5: Get disclosure by ID — database round-trip', () => {
    if (!disclosureId) return;
    const res = http.get(`${BASE_URL}/api/disclosures/${disclosureId}`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'id matches': () => body.id === disclosureId,
      'cve matches': () => body.cve === testCve,
      'title matches': () => body.title === testTitle,
      'severity matches': () => body.severity === testSeverity,
      'has all VulnerabilityDisclosure fields': () => {
        const errs = assertSchema(body, {
          id: 'uuid', org_id: 'uuid', cve: 'string', title: 'string',
          severity: 'string', status: 'string', reporter_public: 'boolean',
          created_at: 'iso8601', updated_at: 'iso8601', received_at: 'iso8601',
        });
        return errs.length === 0;
      },
    });
  });

  // ─── DISC-6: Get disclosure 404 ──────────────────────────────────
  group('DISC-6: Get non-existent disclosure returns 404', () => {
    const res = http.get(`${BASE_URL}/api/disclosures/00000000-0000-0000-0000-999999999999`, { headers });
    check(res, {
      'status 404': (r) => r.status === 404,
    });
  });

  // ─── DISC-7: Update status ───────────────────────────────────────
  group('DISC-7: Update status — change persisted', () => {
    if (!disclosureId) return;
    const res = http.put(`${BASE_URL}/api/disclosures/${disclosureId}/status`, JSON.stringify({ status: 'acknowledged' }), { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'status changed to acknowledged': () => body.status === 'acknowledged',
    });

    // Verify by re-fetching
    const getRes = http.get(`${BASE_URL}/api/disclosures/${disclosureId}`, { headers });
    const getBody = JSON.parse(getRes.body);
    check(null, {
      'GET confirms status change': () => getBody.status === 'acknowledged',
    });
  });

  // ─── DISC-8: Status enum valid ───────────────────────────────────
  group('DISC-8: Status enum values valid', () => {
    const res = http.get(`${BASE_URL}/api/disclosures`, { headers });
    const body = JSON.parse(res.body);
    const data = body.data || [];

    if (data.length > 0) {
      check(null, {
        'all statuses in allowed set': () => data.every(d => VALID_STATUSES.includes(d.status)),
      });
    }
  });

  // ─── DISC-9: SLA compliance check ────────────────────────────────
  group('DISC-9: SLA compliance endpoint', () => {
    const res = http.get(`${BASE_URL}/api/disclosures/sla-compliance`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'has data field': () => Array.isArray(body.data) || body.data === null,
      'has count field': () => typeof body.count === 'number',
    });
  });

  // ─── DISC-10: Created disclosure appears in list ─────────────────
  group('DISC-10: Created disclosure appears in list', () => {
    const res = http.get(`${BASE_URL}/api/disclosures`, { headers });
    const body = JSON.parse(res.body);
    const data = body.data || [];

    check(null, {
      'our CVE appears in list': () => data.some(d => d.cve === testCve),
    });
  });
}
