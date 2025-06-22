import { describe, it, beforeEach, afterAll, expect } from 'vitest';
import request from 'supertest';

process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '10';
process.env.RATE_LIMIT_WINDOW = '1000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
process.env.FRONTEND_URL = 'http://localhost:3000';
process.env.COOKIE_SECURE = 'true';

const {
  app,
  resetUsers,
  resetNonces,
  resetLoginAttempts,
  _authLimiter,
  shutdown,
} = await import('../index.ts');

describe('authentication security headers', () => {
  beforeEach(async () => {
    await resetUsers();
    resetNonces();
    resetLoginAttempts();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
  });

  afterAll(async () => {
    await shutdown();
  });

  it('includes rate limit headers', async () => {
    const res = await request(app)
      .post('/api/login')
      .send({ email: 'n@n.com', password: 'a' });
    expect(res.headers['ratelimit-limit']).toBeDefined();
    expect(res.headers['ratelimit-remaining']).toBeDefined();
    expect(res.headers['ratelimit-reset']).toBeDefined();
  });

  it('responds with proper CORS headers', async () => {
    const res = await request(app)
      .get('/api/token')
      .set('Origin', 'http://localhost:3000');
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
  });

  it('sets auth-specific security headers', async () => {
    const res = await request(app)
      .post('/api/login')
      .send({ email: 'n@n.com', password: 'bad' });
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['pragma']).toBe('no-cache');
  });

  it('uses secure cookie settings', async () => {
    const res = await request(app)
      .post('/api/register')
      .send({ username: 'a', email: 'a@a.com', password: 'Secret1!', confirmPassword: 'Secret1!' });
    const cookie = res.headers['set-cookie'][0];
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Strict');
  });
});
