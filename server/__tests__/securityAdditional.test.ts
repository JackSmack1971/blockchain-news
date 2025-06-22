// Security tests for authentication, session management, headers, and input validation
import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';
import { expectDefaultSecurityHeaders } from './utils/expectSecurityHeaders';
process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '10';
process.env.RATE_LIMIT_WINDOW = '1000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
const { app, resetUsers, resetNonces, resetLoginAttempts, _authLimiter } = await import('../index.ts');

describe('Security Tests', () => {
  beforeEach(async () => {
    await resetUsers();
    resetNonces();
    resetLoginAttempts();
    _authLimiter.resetKey('::ffff:127.0.0.1');
    _authLimiter.resetKey('127.0.0.1');
  });

  describe('Authentication Security', () => {
    it('rejects wallet login without signature', async () => {
      const res = await request(app)
        .post('/api/login/wallet')
        .send({ walletAddress: '0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d0' });
      expect(res.status).toBe(400);
      expect(res.body.error).toContain('signature');
    });

    it('performs constant-time login attempts', async () => {
      const agent = request.agent(app);
      await agent
        .post('/api/register')
        .send({ username: 'tim', email: 'tim@test.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
        .expect(200);
      const start1 = Date.now();
      await agent
        .post('/api/login')
        .send({ email: 'tim@test.com', password: 'wrong' });
      const time1 = Date.now() - start1;
      const start2 = Date.now();
      await agent
        .post('/api/login')
        .send({ email: 'bad@test.com', password: 'password123' });
      const time2 = Date.now() - start2;
      expect(Math.abs(time1 - time2)).toBeLessThan(50);
    });
  });

  describe('Session Security', () => {
    it('prevents session property manipulation', async () => {
      const agent = request.agent(app);
      await agent
        .post('/api/register')
        .send({ username: 'sally', email: 'sally@test.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
        .expect(200);
      await agent
        .post('/api/profile')
        .send({ username: 'newname', id: 'malicious', isAdmin: true, __proto__: { evil: true } })
        .expect(200);
      const profile = await agent.get('/api/token').expect(200);
      expect(profile.body.user.username).toBe('newname');
      expect(profile.body.user.id).not.toBe('malicious');
      expect((profile.body.user as any).isAdmin).toBeUndefined();
    });
  });

  describe('Security Headers', () => {
    it('includes required security headers', async () => {
      const res = await request(app).get('/');
      expectDefaultSecurityHeaders(res);
    });
  });

  describe('Input Validation', () => {
    it('rejects invalid wallet addresses', async () => {
      const invalid = [
        'not-an-address',
        '0xinvalid',
        '0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d',
        '0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d00',
        '',
        null,
      ];
      for (const addr of invalid) {
        const res = await request(app)
          .post('/api/login/wallet')
          .send({ walletAddress: addr });
        expect(res.status).toBe(400);
      }
    });
  });

  describe('Additional Security Cases', () => {
    it('rejects invalid signature formats', async () => {
      const agent = request.agent(app);
      const { Wallet } = await import('ethers');
      const wallet = Wallet.createRandom();
      await agent
        .post('/api/login/wallet/nonce')
        .send({ walletAddress: wallet.address })
        .expect(200);

      const invalidSigs = ['', 'bad-signature', '0x1234'];
      for (const sig of invalidSigs) {
        const res = await agent
          .post('/api/login/wallet')
          .send({ walletAddress: wallet.address, signature: sig });
        expect(res.status).toBe(400);
      }
    });

    it('prevents replay attacks by rejecting reused signature', async () => {
      const agent = request.agent(app);
      const { Wallet } = await import('ethers');
      const wallet = Wallet.createRandom();
      const nonceRes = await agent
        .post('/api/login/wallet/nonce')
        .send({ walletAddress: wallet.address })
        .expect(200);
      const sig = await wallet.signMessage(nonceRes.body.nonce);
      await agent
        .post('/api/login/wallet')
        .send({ walletAddress: wallet.address, signature: sig })
        .expect(200);
      const replay = await agent
        .post('/api/login/wallet')
        .send({ walletAddress: wallet.address, signature: sig });
      expect(replay.status).toBe(400);
    });

    it('expires session after timeout', async () => {
      process.env.COOKIE_MAX_AGE = '50';
      const { app: timeoutApp } = await import('../index.ts');
      const agent = request.agent(timeoutApp);
      await agent
        .post('/api/register')
        .send({ username: 'short', email: 'short@test.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
        .expect(200);
      await new Promise(r => setTimeout(r, 70));
      await agent.get('/api/token').expect(401);
    });

    it('rejects malicious wallet address injection', async () => {
      const res = await request(app)
        .post('/api/login/wallet')
        .send({ walletAddress: '<script>alert(1)</script>' });
      expect(res.status).toBe(400);
    });

    it('sets CSP header on 404 responses', async () => {
      const res = await request(app).get('/no-such-route');
      expect(res.headers['content-security-policy']).toContain("default-src 'self'");
      expect(res.status).toBe(404);
    });
  });
});
