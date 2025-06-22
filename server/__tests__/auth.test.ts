import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';
process.env.SESSION_SECRET = 'test-secret';
const { app, resetUsers } = await import('../index.ts');

describe('auth flow', () => {
  beforeEach(() => {
    resetUsers();
  });

  it('registers, accesses protected route, and logs out', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'alice', email: 'a@a.com', password: 'secret', confirmPassword: 'secret' })
      .expect(200);
    await agent.get('/api/protected').expect(200);
    await agent.post('/api/logout').expect(200);
    await agent.get('/api/protected').expect(401);
  });

  it('rejects invalid login', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'bob', email: 'b@b.com', password: 'secret', confirmPassword: 'secret' })
      .expect(200);
    await agent
      .post('/api/login')
      .send({ email: 'b@b.com', password: 'wrong12' })
      .expect(401);
  });
});
