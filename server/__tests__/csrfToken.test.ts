import { describe, it, beforeEach, afterAll, expect } from 'vitest';
import request from 'supertest';

process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '5';
process.env.RATE_LIMIT_WINDOW = '900000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
process.env.NODE_ENV = 'development';

const { app, resetUsers, resetNonces, _authLimiter, shutdown } = await import('../index.ts');

describe('CSRF token workflow', () => {
  let agent: request.SuperAgentTest;

  beforeEach(async () => {
    await resetUsers();
    resetNonces();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
    agent = request.agent(app);
  });

  afterAll(async () => {
    await shutdown();
  });

  it('accepts requests with valid token and rejects missing or invalid tokens', async () => {
    const csrfRes = await agent.get('/api/csrf-token').expect(200);
    const csrfToken = csrfRes.body.csrfToken;

    await agent
      .post('/api/register')
      .set('X-CSRF-Token', csrfToken)
      .send({ username: 'csrf', email: 'c@c.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);

    await agent
      .post('/api/register')
      .send({ username: 'csrf2', email: 'd@d.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(403);

    await agent
      .post('/api/register')
      .set('X-CSRF-Token', 'invalid')
      .send({ username: 'csrf3', email: 'e@e.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(403);
  });
});
