/**
 * K6-VEX: VEX lifecycle contract tests (7 tests)
 *
 * Verifies: create → approve → publish round-trip, field integrity, 404s.
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

export default function () {
  const token = generateToken();
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Organization-ID': '00000000-0000-0000-0000-000000000001',
  };

  let vexId;
  const testCve = 'CVE-2026-8801';
  const testProductId = 'product:k6-vex-test:1.0.0';

  // ─── VEX-1: Create VEX ───────────────────────────────────────────
  group('VEX-1: Create VEX statement', () => {
    const res = http.post(`${BASE_URL}/api/vex`, JSON.stringify({
      cve: testCve,
      product_id: testProductId,
    }), { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200 || r.status === 201,
      'id is UUID': () => isUUID(body.id),
      'cve matches': () => body.cve === testCve,
      'product_id matches': () => body.product_id === testProductId,
      'default status is draft': () => body.status === 'draft',
    });

    vexId = body.id;
  });

  // ─── VEX-2: List VEX statements ──────────────────────────────────
  group('VEX-2: List VEX statements', () => {
    const res = http.get(`${BASE_URL}/api/vex`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'paginated': () => {
        const data = body.data || body;
        return Array.isArray(data);
      },
      'contains our VEX': () => {
        const data = body.data || [];
        return data.some(v => v.cve === testCve);
      },
    });
  });

  // ─── VEX-3: Approve VEX ──────────────────────────────────────────
  group('VEX-3: Approve VEX', () => {
    if (!vexId) return;
    const res = http.post(`${BASE_URL}/api/vex/${vexId}/approve`, JSON.stringify({}), { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'status changed from draft': () => body.status !== 'draft',
    });
  });

  // ─── VEX-4: Publish VEX ──────────────────────────────────────────
  group('VEX-4: Publish VEX', () => {
    if (!vexId) return;
    const res = http.post(`${BASE_URL}/api/vex/${vexId}/publish`, JSON.stringify({ channel: 'file' }), { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'status is published': () => body.status === 'published',
    });
  });

  // ─── VEX-5: Approve non-existent ─────────────────────────────────
  group('VEX-5: Approve non-existent returns 404', () => {
    const res = http.post(`${BASE_URL}/api/vex/00000000-0000-0000-0000-999999999999/approve`, JSON.stringify({}), { headers });
    check(res, {
      'status 404/400': (r) => r.status === 404 || r.status === 400,
    });
  });

  // ─── VEX-6: Publish non-existent ─────────────────────────────────
  group('VEX-6: Publish non-existent returns 404', () => {
    const res = http.post(`${BASE_URL}/api/vex/00000000-0000-0000-0000-999999999999/publish`, JSON.stringify({ channel: 'file' }), { headers });
    check(res, {
      'status 404/400': (r) => r.status === 404 || r.status === 400,
    });
  });

  // ─── VEX-7: VEX has required fields ──────────────────────────────
  group('VEX-7: VEX has required fields', () => {
    const res = http.get(`${BASE_URL}/api/vex`, { headers });
    const body = JSON.parse(res.body);
    const data = body.data || [];

    if (data.length > 0) {
      check(null, {
        'each has required fields': () => data.every(v => {
          return typeof v.cve === 'string' &&
                 typeof v.product_id === 'string' &&
                 typeof v.status === 'string';
        }),
      });
    }
  });
}
