// Rate limiting performance security tests
import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';
process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '10';
process.env.RATE_LIMIT_WINDOW = '1000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
const { app, resetUsers, resetNonces, resetLoginAttempts, _authLimiter } = await import('../index.ts');

describe('Performance Security', () => {
  beforeEach(async () => {
    await resetUsers();
    resetNonces();
    resetLoginAttempts();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
  });

  it('handles rate limiting correctly', async () => {
    const requests = Array.from({ length: 50 }, () =>
      request(app)
        .post('/api/login')
        .send({ email: 'test@example.com', password: 'wrong' })
    );
    const responses = await Promise.all(requests);
    const rateLimited = responses.filter(r => r.status === 429);
    expect(rateLimited.length).toBeGreaterThan(0);
  });
});
