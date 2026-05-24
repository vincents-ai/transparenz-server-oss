/**
 * K6-COMP: Compliance API contract tests (7 tests)
 *
 * Verifies: status structure, score bounds, SLA list, exploited reporting.
 */
import http from 'k6/http';
import { check, group } from 'k6';
import { BASE_URL } from './common/config.js';
import { generateToken, assertSchema, isISO8601 } from './common/helpers.js';

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

  // ─── COMP-1: Compliance status structure ───────────────────────────
  group('COMP-1: Compliance status structure', () => {
    const res = http.get(`${BASE_URL}/api/compliance/status`, { headers });
    const body = JSON.parse(res.body);

    const errs = assertSchema(body, {
      compliance_score: 'number',
      sla_violations: 'number',
      approaching_deadlines: 'number',
      sovereign_coverage: 'number',
      total_slas: 'number',
      reported_slas: 'number',
      total_vulnerabilities: 'number',
      vulnerabilities_with_source: 'number',
      support_period_months_remaining: 'number',
      support_period_expired: 'boolean',
    });

    check(res, {
      'status 200': (r) => r.status === 200,
      'all 10 fields present': () => errs.length === 0,
    });
  });

  // ─── COMP-2: Score is numeric 0-100 ───────────────────────────────
  group('COMP-2: Score is numeric 0-100', () => {
    const res = http.get(`${BASE_URL}/api/compliance/status`, { headers });
    const body = JSON.parse(res.body);

    check(null, {
      'score >= 0': () => body.compliance_score >= 0,
      'score <= 100': () => body.compliance_score <= 100,
    });
  });

  // ─── COMP-3: SLA tracking list ────────────────────────────────────
  group('COMP-3: SLA tracking list', () => {
    const res = http.get(`${BASE_URL}/api/compliance/sla`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'paginated': () => Array.isArray(body.data) || body.data === null,
      'each SLA has required fields': () => {
        const data = body.data || [];
        if (!Array.isArray(data) || data.length === 0) return true;
        return data.every(sla => {
          const errs = assertSchema(sla, { cve: 'string', deadline: 'string', status: 'string' });
          return errs.length === 0;
        });
      },
    });
  });

  // ─── COMP-4: SLA deadline is ISO8601 ──────────────────────────────
  group('COMP-4: SLA deadline is ISO8601', () => {
    const res = http.get(`${BASE_URL}/api/compliance/sla`, { headers });
    const body = JSON.parse(res.body);
    const data = body.data || [];

    if (Array.isArray(data) && data.length > 0) {
      check(null, {
        'all deadlines are ISO8601': () => data.every(sla => isISO8601(sla.deadline)),
      });
    }
  });

  // ─── COMP-5: Report exploited ─────────────────────────────────────
  group('COMP-5: Report exploited vulnerability', () => {
    const res = http.post(`${BASE_URL}/api/compliance/exploited`, JSON.stringify({ cve: 'CVE-2024-3094' }), { headers });
    check(res, {
      'status 200 or 404 (OSS)': (r) => r.status === 200 || r.status === 201 || r.status === 404,
    });
  });

  // ─── COMP-6: Exploited requires CVE ───────────────────────────────
  group('COMP-6: Exploited rejects empty body', () => {
    const res = http.post(`${BASE_URL}/api/compliance/exploited`, JSON.stringify({}), { headers });
    check(res, {
      'status 400': (r) => r.status === 400,
    });
  });

  // ─── COMP-7: Violations non-negative ──────────────────────────────
  group('COMP-7: Violations count non-negative', () => {
    const res = http.get(`${BASE_URL}/api/compliance/status`, { headers });
    const body = JSON.parse(res.body);
    check(null, {
      'sla_violations >= 0': () => body.sla_violations >= 0,
      'approaching_deadlines >= 0': () => body.approaching_deadlines >= 0,
    });
  });
}
