/**
 * k6 API Contract Tests — shared configuration
 *
 * NOT a load test. VUs=1, iterations=1.
 * Verifies API responses and database round-trip integrity.
 */
export const BASE_URL = __ENV.API_URL || 'http://localhost:28080';
export const JWT_SECRET = __ENV.JWT_SECRET || 'test-jwt-secret-for-playwright-minimum-32-characters';
export const ORG_ID = __ENV.ORG_ID || '00000000-0000-0000-0000-000000000001';
export const ORG_SLUG = __ENV.ORG_SLUG || 'demo';

// HTTP headers for authenticated requests
export function authHeaders(token) {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Organization-ID': ORG_ID,
  };
}

// Multi-part form headers (no Content-Type — k6 sets boundary)
export function authFormHeaders(token) {
  return {
    'Authorization': `Bearer ${token}`,
    'X-Organization-ID': ORG_ID,
  };
}
