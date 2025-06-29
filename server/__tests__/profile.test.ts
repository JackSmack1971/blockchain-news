import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';
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

describe('profile update', () => {
  beforeEach(async () => {
    await resetUsers();
    resetNonces();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
  });

  afterAll(async () => {
    await shutdown();
  });

  it('updates whitelisted fields only', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'carol', email: 'c@c.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);
    await agent.post('/api/profile').send({ username: 'newcarol' }).expect(200);
    const token = await agent.get('/api/token').expect(200);
    expect(token.body.user.username).toBe('newcarol');
  });

  it('prevents id change and prototype pollution', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'dave', email: 'd@d.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);
    const initial = await agent.get('/api/token').expect(200);
    const originalId = initial.body.user.id;
    await agent
      .post('/api/profile')
      .send({ id: 'hacked', '__proto__': { isAdmin: true }, username: 'dave2' })
      .expect(200);
    const after = await agent.get('/api/token').expect(200);
    expect(after.body.user.id).toBe(originalId);
    expect((after.body.user as any).isAdmin).toBeUndefined();
    expect(after.body.user.username).toBe('dave2');
  });
  it('sanitizes malicious input', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'eve', email: 'e@e.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);
    await agent
      .post('/api/profile')
      .send({
        username: '<img src=x onerror="alert(1)"><script>alert(1)</script>evy',
        avatar: 'javascript:alert(1)',
      })
      .expect(200);
    const after = await agent.get('/api/token').expect(200);
    expect(after.body.user.username).not.toMatch(/<script/i);
    expect(after.body.user.username).not.toMatch(/onerror/i);
    expect(after.body.user.avatar).not.toMatch(/javascript:/i);
  });
});
