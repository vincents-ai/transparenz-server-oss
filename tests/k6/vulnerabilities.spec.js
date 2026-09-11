/**
 * K6-VULN: Vulnerability API contract tests (6 tests)
 *
 * Verifies: list, get by CVE, 404, severity enum, KEV fields, filter.
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

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

export default function () {
  const token = generateToken();
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Organization-ID': '00000000-0000-0000-0000-000000000001',
  };

  // ─── VULN-1: List vulnerabilities ─────────────────────────────────
  group('VULN-1: List vulnerabilities', () => {
    const res = http.get(`${BASE_URL}/api/vulnerabilities`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'paginated': () => {
        const data = body.data || body;
        return Array.isArray(data);
      },
      'each has required fields': () => {
        const data = body.data || body;
        if (!Array.isArray(data) || data.length === 0) return true; // no vulns is valid
        return data.every(v => {
          const errs = assertSchema(v, {
            cve: 'string', severity: 'string',
          });
          return errs.length === 0;
        });
      },
    });
  });

  // ─── VULN-2: Get vulnerability by CVE ─────────────────────────────
  group('VULN-2: Get vulnerability by CVE', () => {
    // First get a list to find a CVE
    const listRes = http.get(`${BASE_URL}/api/vulnerabilities`, { headers });
    const listBody = JSON.parse(listRes.body);
    const vulns = listBody.data || listBody;

    if (Array.isArray(vulns) && vulns.length > 0) {
      const cve = vulns[0].cve;
      const res = http.get(`${BASE_URL}/api/vulnerabilities/${encodeURIComponent(cve)}`, { headers });

      check(res, {
        'status 200': (r) => r.status === 200,
        'correct CVE': (r) => {
          const body = JSON.parse(r.body);
          return body.cve === cve;
        },
        'exploited_in_wild is boolean': (r) => {
          const body = JSON.parse(r.body);
          return typeof body.exploited_in_wild === 'boolean';
        },
      });
    }
  });

  // ─── VULN-3: Get vulnerability 404 ───────────────────────────────
  group('VULN-3: Get non-existent CVE returns 404', () => {
    const res = http.get(`${BASE_URL}/api/vulnerabilities/CVE-0000-0000`, { headers });
    check(res, {
      'status 404': (r) => r.status === 404,
    });
  });

  // ─── VULN-4: Severity enum values ─────────────────────────────────
  group('VULN-4: Severity enum values valid', () => {
    const res = http.get(`${BASE_URL}/api/vulnerabilities`, { headers });
    const body = JSON.parse(res.body);
    const vulns = body.data || body;

    if (Array.isArray(vulns) && vulns.length > 0) {
      check(null, {
        'all severities valid': () => vulns.every(v => VALID_SEVERITIES.includes(v.severity?.toLowerCase())),
      });
    }
  });

  // ─── VULN-5: KEV field for exploited vulns ────────────────────────
  group('VULN-5: KEV date set for exploited vulns', () => {
    const res = http.get(`${BASE_URL}/api/vulnerabilities`, { headers });
    const body = JSON.parse(res.body);
    const vulns = body.data || body;

    if (Array.isArray(vulns)) {
      const exploited = vulns.filter(v => v.exploited_in_wild === true);
      if (exploited.length > 0) {
        check(null, {
          'exploited vulns have kev_date_added': () =>
            exploited.every(v => v.kev_date_added && typeof v.kev_date_added === 'string'),
        });
      }
    }
  });

  // ─── VULN-6: Filter by CVE ───────────────────────────────────────
  group('VULN-6: Filter by CVE parameter', () => {
    const res = http.get(`${BASE_URL}/api/vulnerabilities?cve=CVE-2024-3094`, { headers });
    check(res, {
      'status 200': (r) => r.status === 200,
      'results filtered': (r) => {
        const body = JSON.parse(r.body);
        const vulns = body.data || body;
        if (!Array.isArray(vulns) || vulns.length === 0) return true; // no match is valid
        return vulns.every(v => v.cve.includes('CVE-2024-3094'));
      },
    });
  });
}
