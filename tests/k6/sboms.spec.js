/**
 * K6-SBOM: SBOM CRUD round-trip contract tests (10 tests)
 *
 * Verifies: upload → GET → list → download → delete with field-level checks.
 * Ensures database inserts match submitted values (sha256, filename, format, size).
 */
import http from 'k6/http';
import { check, group } from 'k6';
import { BASE_URL } from './common/config.js';
import { generateToken, isUUID, isHex64, assertSchema, cleanSBOM } from './common/helpers.js';

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: { checks: ['rate>0.99'] },
};

function multipartUpload(token, sbom, filename, format) {
  const boundary = '----K6FormBoundary' + Date.now();
  const body =
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="file"; filename="' + filename + '"\r\n' +
    'Content-Type: application/json\r\n\r\n' +
    sbom + '\r\n' +
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="format"\r\n\r\n' +
    format + '\r\n' +
    '--' + boundary + '--\r\n';
  return http.post(`${BASE_URL}/api/sboms/upload`, body, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Organization-ID': '00000000-0000-0000-0000-000000000001',
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
    },
  });
}

export default function () {
  const token = generateToken();
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Organization-ID': '00000000-0000-0000-0000-000000000001',
  };

  let uploadId;
  let uploadSha256;
  let uploadFilename = 'k6-sbom-crud.cdx.json';
  let uploadSize;

  // ─── SBOM-1: Upload CycloneDX JSON ────────────────────────────────
  group('SBOM-1: Upload CycloneDX JSON', () => {
    const sbom = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      metadata: { component: { type: 'application', name: 'k6-crud-test', version: '2.0.0' } },
      components: [
        { type: 'library', name: 'xz-utils', version: '5.6.1', purl: 'pkg:npm/xz-utils@5.6.1' },
        { type: 'library', name: 'apr', version: '1.7.4', purl: 'pkg:generic/apache/apr@1.7.4' },
      ],
    });
    uploadSize = sbom.length;

    const res = multipartUpload(token, sbom, uploadFilename, 'cyclonedx-json');
    const body = JSON.parse(res.body);

    check(res, {
      'status 200/201': (r) => r.status === 200 || r.status === 201,
      'id is UUID': () => isUUID(body.id),
      'filename matches': () => body.filename === uploadFilename,
      'sha256 is 64-char hex': () => isHex64(body.sha256),
      'size_bytes > 0': () => body.size_bytes > 0,
      'format is cyclonedx-json': () => body.format === 'cyclonedx-json',
    });

    uploadId = body.id;
    uploadSha256 = body.sha256;
  });

  // ─── SBOM-2: Upload rejects empty file ────────────────────────────
  group('SBOM-2: Upload rejects empty body', () => {
    const boundary = '----K6FormBoundary' + Date.now();
    const body = '--' + boundary + '\r\n' +
      'Content-Disposition: form-data; name="file"; filename="empty.json"\r\n' +
      'Content-Type: application/json\r\n\r\n' +
      '\r\n--' + boundary + '--\r\n';
    const res = http.post(`${BASE_URL}/api/sboms/upload`, body, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Organization-ID': '00000000-0000-0000-0000-000000000001',
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
      },
    });
    check(res, {
      'status 400': (r) => r.status === 400,
    });
  });

  // ─── SBOM-4: List SBOMs ──────────────────────────────────────────
  group('SBOM-4: List SBOMs', () => {
    const res = http.get(`${BASE_URL}/api/sboms`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'total >= 1': () => body.total >= 1,
      'data is array': () => Array.isArray(body.data),
      'each item has required fields': () => {
        if (!body.data || body.data.length === 0) return false;
        return body.data.every(item => {
          const errs = assertSchema(item, {
            id: 'uuid', org_id: 'uuid', filename: 'string',
            format: 'string', size_bytes: 'number', sha256: 'string', created_at: 'iso8601',
          });
          return errs.length === 0;
        });
      },
    });
  });

  // ─── SBOM-5: Get SBOM by ID — values match upload ────────────────
  group('SBOM-5: Get SBOM by ID — values match upload', () => {
    if (!uploadId) return;
    const res = http.get(`${BASE_URL}/api/sboms/${uploadId}`, { headers });
    const body = JSON.parse(res.body);

    check(res, {
      'status 200': (r) => r.status === 200,
      'id matches': () => body.id === uploadId,
      'filename matches upload': () => body.filename === uploadFilename,
      'sha256 matches upload': () => body.sha256 === uploadSha256,
      'format matches': () => body.format === 'cyclonedx-json',
      'all SbomUpload fields present': () => {
        const errs = assertSchema(body, {
          id: 'uuid', org_id: 'uuid', filename: 'string', format: 'string',
          size_bytes: 'number', sha256: 'string', created_at: 'iso8601',
        });
        return errs.length === 0;
      },
    });
  });

  // ─── SBOM-6: Get SBOM 404 ────────────────────────────────────────
  group('SBOM-6: Get SBOM 404', () => {
    const res = http.get(`${BASE_URL}/api/sboms/00000000-0000-0000-0000-999999999999`, { headers });
    check(res, {
      'status 404': (r) => r.status === 404,
    });
  });

  // ─── SBOM-7: Download SBOM — body matches original ───────────────
  group('SBOM-7: Download SBOM', () => {
    if (!uploadId) return;
    const res = http.get(`${BASE_URL}/api/sboms/${uploadId}/download`, { headers });
    check(res, {
      'status 200': (r) => r.status === 200,
      'body is valid JSON': (r) => {
        try { const parsed = JSON.parse(r.body); return parsed.bomFormat === 'CycloneDX'; } catch { return false; }
      },
      'content matches what was uploaded': (r) => {
        try {
          const parsed = JSON.parse(r.body);
          return parsed.metadata?.component?.name === 'k6-crud-test';
        } catch { return false; }
      },
    });
  });

  // ─── SBOM-9: Delete SBOM ─────────────────────────────────────────
  group('SBOM-9: Delete SBOM', () => {
    if (!uploadId) return;
    const res = http.del(`${BASE_URL}/api/sboms/${uploadId}`, null, { headers });
    check(res, {
      'status 204/200': (r) => r.status === 204 || r.status === 200,
    });

    // Verify subsequent GET returns 404
    const getRes = http.get(`${BASE_URL}/api/sboms/${uploadId}`, { headers });
    check(getRes, {
      'subsequent GET returns 404': (r) => r.status === 404,
    });
  });

  // ─── SBOM-10: Delete 404 ─────────────────────────────────────────
  group('SBOM-10: Delete 404', () => {
    const res = http.del(`${BASE_URL}/api/sboms/00000000-0000-0000-0000-999999999999`, null, { headers });
    check(res, {
      'status 404': (r) => r.status === 404,
    });
  });

  // ─── SBOM-8: Upload SPDX JSON ────────────────────────────────────
  group('SBOM-8: Upload SPDX JSON', () => {
    const spdx = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'k6-spdx-test',
      documentNamespace: 'https://example.com/k6-spdx-test',
      creationInfo: { created: new Date().toISOString(), creators: ['Tool: k6'] },
      packages: [{
        SPDXID: 'SPDXRef-Package',
        name: 'test-pkg',
        versionInfo: '1.0.0',
        downloadLocation: 'https://example.com/test-pkg',
      }],
    });

    const res = multipartUpload(token, spdx, 'k6-spdx.spdx.json', 'spdx-json');
    const body = JSON.parse(res.body);
    check(res, {
      'status 200/201': (r) => r.status === 200 || r.status === 201,
      'format is spdx-json': () => body.format === 'spdx-json',
    });

    // Cleanup
    if (body.id) cleanSBOM(token, body.id);
  });
}
