import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';
process.env.SESSION_SECRET = 'test-secret';
const { app, resetUsers, resetNonces, _nonceStore } = await import('../index.ts');

describe('auth flow', () => {
  beforeEach(() => {
    resetUsers();
    resetNonces();
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
    const signature = await wallet.signMessage(nonceRes.body.nonce);
    await agent
      .post('/api/login/wallet')
      .send({ walletAddress: wallet.address, signature })
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
    const badWallet = Wallet.createRandom();
    const badSig = await badWallet.signMessage(nonceRes.body.nonce);
    await agent
      .post('/api/login/wallet')
      .send({ walletAddress: wallet.address, signature: badSig })
      .expect(401);
    const sig = await wallet.signMessage(nonceRes.body.nonce);
    await agent
      .post('/api/login/wallet')
      .send({ walletAddress: wallet.address, signature: sig })
      .expect(200);
    await agent
      .post('/api/login/wallet')
      .send({ walletAddress: wallet.address, signature: sig })
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
    const signature = await wallet.signMessage(nonceRes.body.nonce);
    await agent
      .post('/api/login/wallet')
      .send({ walletAddress: wallet.address, signature })
      .expect(400);
  });
});
