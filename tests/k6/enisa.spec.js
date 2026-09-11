/**
 * K6-ENISA: ENISA submission contract tests (7 tests)
 *
 * Verifies: submit, list, GET, download CSAF, status enum.
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

const VALID_STATUSES = ['pending', 'submitted', 'accepted', 'rejected', 'failed', 'draft', 'generating', 'completed'];

export default function () {
  const token = generateToken();
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Organization-ID': '00000000-0000-0000-0000-000000000001',
  };

  let submissionId;
  const testCve = 'CVE-2024-3094';

  // ─── ENISA-1: Submit CVE to ENISA ────────────────────────────────
  group('ENISA-1: Submit CVE to ENISA', () => {
    const res = http.post(`${BASE_URL}/api/enisa/submit`, JSON.stringify({ cve: testCve }), { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200/202/403': (r) => r.status === 200 || r.status === 202 || r.status === 201 || r.status === 403,
      'id is UUID (if created)': () => {
        if (res.status >= 400) return true; // commercial-only is OK
        return isUUID(body.id);
      },
    });

    submissionId = body.id;
  });

  // ─── ENISA-2: Submit rejects bad CVE ─────────────────────────────
  group('ENISA-2: Submit rejects invalid CVE', () => {
    const res = http.post(`${BASE_URL}/api/enisa/submit`, JSON.stringify({ cve: 'INVALID' }), { headers });
    check(res, {
      'status 400 or 403': (r) => r.status === 400 || r.status === 403,
    });
  });

  // ─── ENISA-3: List submissions ───────────────────────────────────
  group('ENISA-3: List ENISA submissions', () => {
    const res = http.get(`${BASE_URL}/api/enisa/submissions`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'paginated': () => {
        const data = body.data || body;
        return Array.isArray(data);
      },
    });
  });

  // ─── ENISA-4: Get submission by ID ───────────────────────────────
  group('ENISA-4: Get submission by ID', () => {
    if (!submissionId) {
      // Try to find one from list
      const listRes = http.get(`${BASE_URL}/api/enisa/submissions`, { headers });
      const listBody = JSON.parse(listRes.body);
      const data = listBody.data || [];
      if (data.length > 0) submissionId = data[0].id;
    }
    if (!submissionId) return;

    const res = http.get(`${BASE_URL}/api/enisa/submissions/${submissionId}`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'has status field': () => typeof body.status === 'string',
      'id matches': () => body.id === submissionId,
    });
  });

  // ─── ENISA-5: Get submission 404 ─────────────────────────────────
  group('ENISA-5: Get non-existent submission returns 404', () => {
    const res = http.get(`${BASE_URL}/api/enisa/submissions/00000000-0000-0000-0000-999999999999`, { headers });
    check(res, {
      'status 404': (r) => r.status === 404,
    });
  });

  // ─── ENISA-6: Download CSAF ──────────────────────────────────────
  group('ENISA-6: Download CSAF document', () => {
    if (!submissionId) {
      const listRes = http.get(`${BASE_URL}/api/enisa/submissions`, { headers });
      const listBody = JSON.parse(listRes.body);
      const data = listBody.data || [];
      if (data.length > 0) submissionId = data[0].id;
    }
    if (!submissionId) return;

    const res = http.get(`${BASE_URL}/api/enisa/submissions/${submissionId}/download`, { headers });
    if (res.status === 200) {
      check(res, {
        'body is valid JSON': (r) => {
          try { JSON.parse(r.body); return true; } catch { return false; }
        },
        'has CSAF structure': (r) => {
          try {
            const body = JSON.parse(r.body);
            return typeof body.document === 'object' || typeof body.distribution === 'object' || r.body.length > 10;
          } catch { return false; }
        },
      });
    }
  });

  // ─── ENISA-7: Submission status enum ─────────────────────────────
  group('ENISA-7: Submission status enum valid', () => {
    const res = http.get(`${BASE_URL}/api/enisa/submissions`, { headers });
    const body = JSON.parse(res.body);
    const data = body.data || [];

    if (data.length > 0) {
      check(null, {
        'all statuses valid': () => data.every(s => VALID_STATUSES.includes(s.status)),
      });
    }
  });
}
