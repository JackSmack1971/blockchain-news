import { describe, it, beforeEach, afterAll, vi } from 'vitest';
import request from 'supertest';

process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '5';
process.env.RATE_LIMIT_WINDOW = '60000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
process.env.NODE_ENV = 'test';

const { app, resetUsers, resetNonces, _authLimiter, shutdown } = await import('../index.ts');

describe('rate limiter', () => {
  let agent: request.SuperAgentTest;

  beforeEach(async () => {
    await resetUsers();
    resetNonces();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
    vi.useFakeTimers();
    agent = request.agent(app);
  });

  afterAll(async () => {
    vi.useRealTimers();
    await shutdown();
  });

  it('blocks after 5 attempts then resets after window', async () => {
    for (let i = 0; i < 5; i++) {
      await agent.post('/api/login').send({ email: 'a@a.com', password: 'a' });
    }
    await agent.post('/api/login').send({ email: 'a@a.com', password: 'a' }).expect(429);
    vi.advanceTimersByTime(60000);
    await agent.post('/api/login').send({ email: 'a@a.com', password: 'a' }).expect(401);
  });
});
