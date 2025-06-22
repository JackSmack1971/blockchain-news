import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';
process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
const { app, resetUsers, resetNonces, resetLoginAttempts, _authLimiter } = await import('../index');

describe('Security Monitoring', () => {
  beforeEach(async () => {
    await resetUsers();
    resetNonces();
    resetLoginAttempts();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
  });

  it('collects metrics for failed login', async () => {
    await request(app).post('/api/login').send({ email: 'bad@example.com', password: 'x' });
    const res = await request(app).get('/metrics');
    expect(res.text).toContain('security_events_total');
    expect(res.text).toContain('failed_logins_total');
  });
});
