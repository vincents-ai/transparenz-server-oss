/**
 * K6-AUDIT: Audit verification + export contract tests (5 tests)
 *
 * Verifies: audit chain verification, CSV/PDF export, enriched SBOM export.
 */
import http from 'k6/http';
import { check, group } from 'k6';
import { BASE_URL } from './common/config.js';
import { generateToken, seedSBOM, cleanSBOM } from './common/helpers.js';

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

  const today = new Date().toISOString().split('T')[0];
  const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0];

  // ─── AUDIT-1: Verify audit chain ─────────────────────────────────
  group('AUDIT-1: Verify audit chain', () => {
    const res = http.get(`${BASE_URL}/api/audit/verify?start=${weekAgo}&end=${today}`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'verified is boolean': () => typeof body.verified === 'boolean',
      'total_events >= 0': () => typeof body.total_events === 'number' && body.total_events >= 0,
    });
  });

  // ─── AUDIT-2: Verify requires dates ──────────────────────────────
  group('AUDIT-2: Verify without dates returns 400', () => {
    const res = http.get(`${BASE_URL}/api/audit/verify`, { headers });
    check(res, {
      'status 400': (r) => r.status === 400,
    });
  });

  // ─── AUDIT-3: Export audit CSV ───────────────────────────────────
  group('AUDIT-3: Export audit report as CSV', () => {
    const res = http.get(`${BASE_URL}/api/export/audit?format=csv&start=${weekAgo}&end=${today}`, { headers });
    check(res, {
      'status 200': (r) => r.status === 200,
      'content-type csv': (r) => {
        const ct = r.headers['Content-Type'] || '';
        return ct.includes('text/csv') || ct.includes('application/csv') || ct.includes('text/plain');
      },
      'body has content': (r) => r.body.length > 0,
    });
  });

  // ─── AUDIT-4: Export audit PDF ───────────────────────────────────
  group('AUDIT-4: Export audit report as PDF', () => {
    const res = http.get(`${BASE_URL}/api/export/audit?format=pdf&start=${weekAgo}&end=${today}`, { headers });
    check(res, {
      'status 200 or 400 (PDF is commercial-only)': (r) => r.status === 200 || r.status === 400,
      'body has content': (r) => r.body.length > 0,
    });
  });

  // ─── AUDIT-5: Export enriched SBOM ──────────────────────────────;

  // ─── AUDIT-5: Export enriched SBOM ──────────────────────────────
  group('AUDIT-5: Export enriched SBOM', () => {
    // Seed an SBOM to export
    const sbom = seedSBOM(token, 'k6-audit-export');
    const res = http.get(`${BASE_URL}/api/export/enriched-sbom/${sbom.id}`, { headers });

    check(res, {
      'status 200': (r) => r.status === 200,
      'body is JSON': (r) => {
        try { JSON.parse(r.body); return true; } catch { return false; }
      },
    });

    cleanSBOM(token, sbom.id);
  });
}
