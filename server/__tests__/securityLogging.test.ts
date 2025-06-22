import { describe, it, beforeEach, expect, afterEach } from 'vitest';
import request from 'supertest';
import fs from 'fs/promises';
import { existsSync, statSync } from 'fs';

process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '1';
process.env.RATE_LIMIT_WINDOW = '1000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';

const { app, resetUsers, resetNonces, resetLoginAttempts, _authLimiter, shutdown } = await import('../index.ts');
import { metrics, resetMetrics } from '../logging';

const logPath = 'logs/security.log';

async function readLog(): Promise<any> {
  const data = await fs.readFile(logPath, 'utf8');
  const lines = data.trim().split('\n');
  return JSON.parse(lines[lines.length - 1]);
}

describe('security logging', () => {
  beforeEach(async () => {
    await fs.rm('logs', { recursive: true, force: true });
    await resetUsers();
    resetNonces();
    resetLoginAttempts();
    resetMetrics();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
  });

  afterEach(async () => {
    await shutdown();
  });

  it('logs failed login attempts', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/login')
      .send({ email: 'none@test.com', password: 'bad' })
      .expect(401);
    expect(existsSync(logPath)).toBe(true);
    const entry = await readLog();
    expect(entry.event).toBe('failed_login');
    expect(metrics.failedLogin).toBe(1);
  });

  it('logs rate limit violations', async () => {
    const agent = request.agent(app);
    await agent.post('/api/login').send({ email: 'a@a.com', password: 'b' });
    await agent.post('/api/login').send({ email: 'a@a.com', password: 'b' });
    const entry = await readLog();
    expect(entry.event).toBe('rate_limit_exceeded');
    const mode = statSync(logPath).mode & 0o777;
    expect(mode).toBe(0o600);
  });
});
