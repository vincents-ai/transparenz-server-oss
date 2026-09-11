/**
 * K6-SYS: System endpoint contract tests (4 tests)
 *
 * Verifies health, readiness, metrics, and 404 handling.
 */
import http from 'k6/http';
import { check, group } from 'k6';
import { BASE_URL } from './common/config.js';

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: { checks: ['rate>0.99'] },
};

export default function () {
  // ─── SYS-1: Health check ──────────────────────────────────────────
  group('SYS-1: Health check', () => {
    const res = http.get(`${BASE_URL}/health`);
    check(res, {
      'status 200': (r) => r.status === 200,
      'body is JSON': (r) => {
        try { JSON.parse(r.body); return true; } catch { return false; }
      },
      'has status or detail': (r) => {
        const body = JSON.parse(r.body);
        return typeof body.status === 'number' || typeof body.detail === 'string';
      },
    });
  });

  // ─── SYS-2: Readiness check ──────────────────────────────────────
  group('SYS-2: Readiness check', () => {
    const res = http.get(`${BASE_URL}/readyz`);
    check(res, {
      'status 200': (r) => r.status === 200,
      'body is JSON': (r) => {
        try { JSON.parse(r.body); return true; } catch { return false; }
      },
    });
  });

  // ─── SYS-3: Metrics endpoint (requires auth) ─────────────────────
  group('SYS-3: Metrics endpoint', () => {
    // Metrics is behind BasicAuth — 401 without credentials is valid
    const res = http.get(`${BASE_URL}/metrics`);
    check(res, {
      'status 200 or 401': (r) => r.status === 200 || r.status === 401,
    });
  });

  // ─── SYS-4: 404 for unknown route ────────────────────────────────
  group('SYS-4: 404 for unknown route', () => {
    const res = http.get(`${BASE_URL}/api/nonexistent-route-xyz`);
    check(res, {
      'status 404': (r) => r.status === 404,
    });
  });
}
