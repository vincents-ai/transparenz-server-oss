/**
 * k6 API Contract Tests — shared helpers
 *
 * JWT generation, field validation, schema assertions.
 */
import http from 'k6/http';
import { check, fail } from 'k6';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';
import { BASE_URL, JWT_SECRET, ORG_ID } from './config.js';

// ─── JWT Generation ────────────────────────────────────────────────

function base64url(str) {
  return encoding.b64encode(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function generateToken(roles = ['admin', 'compliance_officer']) {
  const header = JSON.stringify({ alg: 'HS256', typ: 'JWT' });
  const now = Math.floor(Date.now() / 1000);
  const payload = JSON.stringify({
    sub: 'k6-test-user',
    email: 'k6@test.local',
    org_id: ORG_ID,
    org_slug: 'demo',
    roles,
    account_id: 'k6-test-account',
    plan_slug: 'standard',
    iat: now,
    exp: now + 3600,
    iss: 'billing-auth-service',
    aud: 'transparenz-suite',
  });

  const h = base64url(header);
  const p = base64url(payload);
  const sigBytes = crypto.hmac('sha256', JWT_SECRET, `${h}.${p}`, 'binary');
  const sigB64 = encoding.b64encode(sigBytes, 'raw').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  return `${h}.${p}.${sigB64}`;
}

// ─── Validation Helpers ────────────────────────────────────────────

export function isUUID(str) {
  if (typeof str !== 'string') return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str);
}

export function isISO8601(str) {
  if (typeof str !== 'string') return false;
  const d = new Date(str);
  return !isNaN(d.getTime());
}

export function isHex64(str) {
  if (typeof str !== 'string') return false;
  return /^[0-9a-f]{64}$/i.test(str);
}

// ─── Schema Assertions ─────────────────────────────────────────────

/**
 * Assert that a response object has the required fields with expected types.
 * types: 'string', 'number', 'boolean', 'uuid', 'iso8601', 'hex64', 'array', 'object'
 */
export function assertSchema(obj, fields, prefix = '') {
  const errors = [];
  for (const [name, expectedType] of Object.entries(fields)) {
    const val = obj[name];
    const label = prefix ? `${prefix}.${name}` : name;

    if (val === undefined || val === null) {
      errors.push(`${label}: missing`);
      continue;
    }

    switch (expectedType) {
      case 'string':
        if (typeof val !== 'string') errors.push(`${label}: expected string, got ${typeof val}`);
        break;
      case 'number':
        if (typeof val !== 'number') errors.push(`${label}: expected number, got ${typeof val}`);
        break;
      case 'boolean':
        if (typeof val !== 'boolean') errors.push(`${label}: expected boolean, got ${typeof val}`);
        break;
      case 'uuid':
        if (!isUUID(val)) errors.push(`${label}: not a valid UUID: "${val}"`);
        break;
      case 'iso8601':
        if (!isISO8601(val)) errors.push(`${label}: not ISO8601: "${val}"`);
        break;
      case 'hex64':
        if (!isHex64(val)) errors.push(`${label}: not 64-char hex: "${val}"`);
        break;
      case 'array':
        if (!Array.isArray(val)) errors.push(`${label}: expected array, got ${typeof val}`);
        break;
      case 'object':
        if (typeof val !== 'object' || Array.isArray(val)) errors.push(`${label}: expected object`);
        break;
    }
  }
  return errors;
}

/**
 * Assert paginated response structure: { data: [...], total, limit, offset }
 */
export function assertPageSchema(obj) {
  return assertSchema(obj, {
    data: 'array',
    total: 'number',
    limit: 'number',
    offset: 'number',
  });
}

// ─── API Helpers ────────────────────────────────────────────────────

/**
 * Upload a CycloneDX SBOM, return the response body.
 */
export function seedSBOM(token, name = 'k6-test-app') {
  const sbom = JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: { component: { type: 'application', name, version: '1.0.0' } },
    components: [
      { type: 'library', name: 'xz-utils', version: '5.6.1', purl: 'pkg:npm/xz-utils@5.6.1' },
    ],
  });

  const boundary = '----K6FormBoundary' + Date.now();
  const body =
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="file"; filename="' + name + '.cdx.json"\r\n' +
    'Content-Type: application/json\r\n\r\n' +
    sbom + '\r\n' +
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="format"\r\n\r\n' +
    'cyclonedx-json\r\n' +
    '--' + boundary + '--\r\n';

  const res = http.post(`${BASE_URL}/api/sboms/upload`, body, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Organization-ID': ORG_ID,
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
    },
  });

  if (res.status !== 200 && res.status !== 201) {
    fail(`seedSBOM failed: ${res.status} ${res.body}`);
  }
  return JSON.parse(res.body);
}

/**
 * Delete an SBOM by ID.
 */
export function cleanSBOM(token, id) {
  http.del(`${BASE_URL}/api/sboms/${id}`, null, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Organization-ID': ORG_ID,
    },
  });
}

/**
 * Create a disclosure, return the response body.
 */
export function seedDisclosure(token, cve = 'CVE-2026-9001') {
  const res = http.post(`${BASE_URL}/api/disclosures`, JSON.stringify({
    cve,
    title: `k6 test disclosure for ${cve}`,
    severity: 'high',
  }), {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'X-Organization-ID': ORG_ID,
    },
  });
  if (res.status !== 200 && res.status !== 201) {
    fail(`seedDisclosure failed: ${res.status} ${res.body}`);
  }
  return JSON.parse(res.body);
}
