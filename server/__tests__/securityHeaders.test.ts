import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';

process.env.SESSION_SECRET = 'test-secret';
process.env.RATE_LIMIT_MAX = '10';
process.env.RATE_LIMIT_WINDOW_MS = '1000';
const { app, resetUsers, resetNonces, _authLimiter } = await import('../index.ts');

describe('security headers', () => {
  beforeEach(() => {
    resetUsers();
    resetNonces();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
  });

  it('sets comprehensive security headers', async () => {
    const res = await request(app).get('/api/token').expect(401);
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-xss-protection']).toBe('1; mode=block');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
    expect(res.headers['x-permitted-cross-domain-policies']).toBe('none');
    expect(res.headers['cross-origin-embedder-policy']).toBe('require-corp');
    expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
  });
});
