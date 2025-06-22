import { expect } from 'vitest';
import { Response } from 'supertest';

export function expectDefaultSecurityHeaders(res: Response): void {
  const h = res.headers;
  expect(h['x-frame-options']).toBe('DENY');
  expect(h['x-content-type-options']).toBe('nosniff');
  expect(h['x-xss-protection']).toBe('1; mode=block');
  expect(h['referrer-policy']).toBe('strict-origin-when-cross-origin');
  expect(h['content-security-policy']).toContain("default-src 'self'");
  expect(h['x-permitted-cross-domain-policies']).toBe('none');
  expect(h['cross-origin-embedder-policy']).toBe('require-corp');
  expect(h['cross-origin-opener-policy']).toBe('same-origin');
  expect(h['strict-transport-security']).toContain('max-age');
  expect(h['permissions-policy']).toContain('geolocation=()');
}
