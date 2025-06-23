import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';
process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '10';
process.env.RATE_LIMIT_WINDOW = '1000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
process.env.SIGNIN_DOMAIN = 'localhost:3001';
process.env.SIGNIN_CHAIN_ID = '1';
const { app, resetUsers, shutdown } = await import('../index.ts');
const {
  resetNonces,
  resetLoginAttempts,
  _nonceStore,
  _authLimiter,
} = await import('../auth.ts');

describe('auth flow', () => {
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

  it('registers, accesses protected route, and logs out', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'alice', email: 'a@a.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);
    await agent.get('/api/protected').expect(200);
    await agent.post('/api/logout').expect(200);
    await agent.get('/api/protected').expect(401);
  });

  it('rejects invalid login', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'bob', email: 'b@b.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);
    await agent
      .post('/api/login')
      .send({ email: 'b@b.com', password: 'Wrong123!' })
      .expect(401);
  });

  it('authenticates with wallet signature', async () => {
    const agent = request.agent(app);
    const { Wallet } = await import('ethers');
    const wallet = Wallet.createRandom();
    const nonceRes = await agent
      .post('/api/login/wallet/nonce')
      .send({ walletAddress: wallet.address })
      .expect(200);
    const message = `${process.env.SIGNIN_DOMAIN} wants you to sign in with your Ethereum account:\n${wallet.address}\n\nSign in to BlockchainNews\n\nURI: http://${process.env.SIGNIN_DOMAIN}\nVersion: 1\nChain ID: 1\nNonce: ${nonceRes.body.nonce}\nIssued At: ${new Date().toISOString()}`;
    const signature = await wallet.signMessage(message);
    await agent
      .post('/api/login/wallet')
      .send({ message, signature })
      .expect(200);
    const token = await agent.get('/api/token').expect(200);
    expect(token.body.user.walletAddress).toBe(wallet.address);
  });

  it('rejects invalid wallet signature and nonce reuse', async () => {
    const agent = request.agent(app);
    const { Wallet } = await import('ethers');
    const wallet = Wallet.createRandom();
    const nonceRes = await agent
      .post('/api/login/wallet/nonce')
      .send({ walletAddress: wallet.address })
      .expect(200);
    const msg = `${process.env.SIGNIN_DOMAIN} wants you to sign in with your Ethereum account:\n${wallet.address}\n\nSign in to BlockchainNews\n\nURI: http://${process.env.SIGNIN_DOMAIN}\nVersion: 1\nChain ID: 1\nNonce: ${nonceRes.body.nonce}\nIssued At: ${new Date().toISOString()}`;
    const badWallet = Wallet.createRandom();
    const badSig = await badWallet.signMessage(msg);
    await agent
      .post('/api/login/wallet')
      .send({ message: msg, signature: badSig })
      .expect(401);
    const sig = await wallet.signMessage(msg);
    await agent
      .post('/api/login/wallet')
      .send({ message: msg, signature: sig })
      .expect(200);
    await agent
      .post('/api/login/wallet')
      .send({ message: msg, signature: sig })
      .expect(400);
  });

  it('fails when nonce expired', async () => {
    const agent = request.agent(app);
    const { Wallet } = await import('ethers');
    const wallet = Wallet.createRandom();
    const nonceRes = await agent
      .post('/api/login/wallet/nonce')
      .send({ walletAddress: wallet.address })
      .expect(200);
    const entry = _nonceStore.get(wallet.address.toLowerCase());
    if (entry) entry.expiresAt = Date.now() - 1;
    const msg = `${process.env.SIGNIN_DOMAIN} wants you to sign in with your Ethereum account:\n${wallet.address}\n\nSign in to BlockchainNews\n\nURI: http://${process.env.SIGNIN_DOMAIN}\nVersion: 1\nChain ID: 1\nNonce: ${nonceRes.body.nonce}\nIssued At: ${new Date().toISOString()}`;
    const signature = await wallet.signMessage(msg);
    await agent
      .post('/api/login/wallet')
      .send({ message: msg, signature })
      .expect(400);
  });

  it('rejects invalid wallet address format', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/login/wallet/nonce')
      .send({ walletAddress: '0x123' })
      .expect(400);
  });

  it('rejects wallet address with bad checksum', async () => {
    const agent = request.agent(app);
    const { Wallet } = await import('ethers');
    const wallet = Wallet.createRandom();
    const bad = wallet.address.toUpperCase();
    await agent.post('/api/login/wallet/nonce').send({ walletAddress: bad }).expect(400);
  });

  it('normalizes lowercase wallet addresses', async () => {
    const agent = request.agent(app);
    const { Wallet } = await import('ethers');
    const wallet = Wallet.createRandom();
    const nonceRes = await agent
      .post('/api/login/wallet/nonce')
      .send({ walletAddress: wallet.address.toLowerCase() })
      .expect(200);
    const msg = `${process.env.SIGNIN_DOMAIN} wants you to sign in with your Ethereum account:\n${wallet.address.toLowerCase()}\n\nSign in to BlockchainNews\n\nURI: http://${process.env.SIGNIN_DOMAIN}\nVersion: 1\nChain ID: 1\nNonce: ${nonceRes.body.nonce}\nIssued At: ${new Date().toISOString()}`;
    const sig = await wallet.signMessage(msg);
    const res = await agent
      .post('/api/login/wallet')
      .send({ message: msg, signature: sig })
      .expect(200);
    expect(res.body.walletAddress).toBe(wallet.address);
  });

  it('rate limits login attempts', async () => {
    const agent = request.agent(app);
    for (let i = 0; i < 10; i++) {
      await agent.post('/api/login').send({ email: 'x@x.com', password: 'a' });
    }
    await agent
      .post('/api/login')
      .send({ email: 'x@x.com', password: 'a' })
      .expect(429);
  });

  it('locks account after repeated failed logins', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'lock', email: 'lock@test.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);
    for (let i = 0; i < 5; i++) {
      await agent
        .post('/api/login')
        .send({ email: 'lock@test.com', password: 'Wrong123!' })
        .expect(401);
    }
    await agent
      .post('/api/login')
      .send({ email: 'lock@test.com', password: 'Wrong123!' })
      .expect(403);
  });

  it('performs constant-time login to prevent enumeration', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'timing', email: 't@test.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);
    const start1 = Date.now();
    await agent
      .post('/api/login')
      .send({ email: 't@test.com', password: 'Wrong123!' })
      .expect(401);
    const durationExisting = Date.now() - start1;
    const start2 = Date.now();
    await agent
      .post('/api/login')
      .send({ email: 'nosuch@test.com', password: 'Wrong123!' })
      .expect(401);
    const durationNon = Date.now() - start2;
    expect(Math.abs(durationExisting - durationNon)).toBeLessThan(200);
  });

  it('stores password hashes with cost factor 12', async () => {
    const agent = request.agent(app);
    await agent
      .post('/api/register')
      .send({ username: 'hash', email: 'hash@test.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);
    const { findUserByEmail } = await import('../db');
    const user = await findUserByEmail('hash@test.com');
    expect(user.password_hash).toMatch(/^\$2[abxy]\$12\$/);
  });
});
