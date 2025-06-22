import { describe, it, beforeEach } from 'vitest';
import request from 'supertest';
import { expectDefaultSecurityHeaders } from './utils/expectSecurityHeaders';

process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '10';
process.env.RATE_LIMIT_WINDOW = '1000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
const {
  app,
  resetUsers,
  resetNonces,
  _authLimiter,
  shutdown,
} = await import('../index.ts');

describe('security headers', () => {
  beforeEach(async () => {
    await resetUsers();
    resetNonces();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
  });

  afterAll(async () => {
    await shutdown();
  });

  it('sets comprehensive security headers', async () => {
    const res = await request(app).get('/api/token').expect(401);
    expectDefaultSecurityHeaders(res);
  });
});
