import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import { Wallet } from 'ethers';

let app: any;
let resetUsers: any;
let shutdown: any;
let resetNonces: any;
let _authLimiter: any;
let mockRedis: any;

class MockRedis {
  store = new Map<string, string>();
  exists = vi.fn(async (key: string) => (this.store.has(key) ? 1 : 0));
  set = vi.fn(async (key: string, value: string, mode: string, ttl: number) => {
    this.store.set(key, value);
  });
}

const buildMessage = (domain: string, address: string, nonce: string, chain = 1, ts = new Date().toISOString()) =>
  `${domain} wants you to sign in with your Ethereum account:\n${address}\n\nSign in to BlockchainNews\n\nURI: http://${domain}\nVersion: 1\nChain ID: ${chain}\nNonce: ${nonce}\nIssued At: ${ts}`;

beforeEach(async () => {
  mockRedis = new MockRedis();
  vi.doMock('ioredis', () => ({ default: vi.fn(() => mockRedis) }));
  const users: any[] = [];
  vi.doMock('../db', () => ({
    initDb: vi.fn(),
    resetDatabase: vi.fn(async () => {
      users.length = 0;
    }),
    closePool: vi.fn(),
    createUser: vi.fn(async (user: any) => {
      users.push(user);
    }),
    findUserByEmail: vi.fn(async (email: string) => users.find(u => u.email === email) || null),
    findUserByWallet: vi.fn(async (addr: string) => users.find(u => u.walletAddress === addr) || null),
  }));

  process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
  process.env.RATE_LIMIT_MAX = '10';
  process.env.RATE_LIMIT_WINDOW = '1000';
  process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
  process.env.SIGNIN_DOMAIN = 'localhost:3001';
  process.env.SIGNIN_CHAIN_ID = '1';
  process.env.REDIS_URL = 'redis://localhost:6379';

  const index = await import('../index.ts');
  app = index.app;
  resetUsers = index.resetUsers;
  shutdown = index.shutdown;
  const auth = await import('../auth.ts');
  resetNonces = auth.resetNonces;
  _authLimiter = auth._authLimiter;

  await resetUsers();
  resetNonces();
  _authLimiter.resetKey('::ffff:127.0.0.1');
  _authLimiter.resetKey('127.0.0.1');
});

afterEach(async () => {
  vi.resetModules();
  await shutdown();
});

describe('web3Auth integration', () => {
  it('allows login with valid domain, timestamp and chain id', async () => {
    const agent = request.agent(app);
    const wallet = Wallet.createRandom();
    const nonceRes = await agent
      .post('/api/login/wallet/nonce')
      .send({ walletAddress: wallet.address })
      .expect(200);
    const message = buildMessage(process.env.SIGNIN_DOMAIN!, wallet.address, nonceRes.body.nonce);
    const sig = await wallet.signMessage(message);
    const res = await agent
      .post('/api/login/wallet')
      .send({ message, signature: sig })
      .expect(200);
    expect(res.body.walletAddress).toBe(wallet.address);
    expect(mockRedis.set).toHaveBeenCalled();
  });

  it('rejects stale timestamps and reused signatures', async () => {
    const agent = request.agent(app);
    const wallet = Wallet.createRandom();
    const nonceRes = await agent
      .post('/api/login/wallet/nonce')
      .send({ walletAddress: wallet.address })
      .expect(200);
    const oldTs = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const staleMsg = buildMessage(process.env.SIGNIN_DOMAIN!, wallet.address, nonceRes.body.nonce, 1, oldTs);
    const staleSig = await wallet.signMessage(staleMsg);
    const staleRes = await agent
      .post('/api/login/wallet')
      .send({ message: staleMsg, signature: staleSig })
      .expect(400);
    expect(staleRes.body.error).toBe('Message expired');

    const freshMsg = buildMessage(process.env.SIGNIN_DOMAIN!, wallet.address, nonceRes.body.nonce);
    const sig = await wallet.signMessage(freshMsg);
    await agent.post('/api/login/wallet').send({ message: freshMsg, signature: sig }).expect(200);
    const reuseRes = await agent
      .post('/api/login/wallet')
      .send({ message: freshMsg, signature: sig })
      .expect(400);
    expect(reuseRes.body.error).toMatch(/Signature already used/);
    expect(mockRedis.exists).toHaveBeenCalled();
  });

  it('rejects domain mismatch and invalid chain id', async () => {
    const agent = request.agent(app);
    const wallet = Wallet.createRandom();
    const nonce1 = await agent
      .post('/api/login/wallet/nonce')
      .send({ walletAddress: wallet.address })
      .then(r => r.body.nonce);
    const ts = new Date().toISOString();

    const badDomainMsg = buildMessage('evil.com', wallet.address, nonce1, 1, ts);
    const badDomainSig = await wallet.signMessage(badDomainMsg);
    const res1 = await agent
      .post('/api/login/wallet')
      .send({ message: badDomainMsg, signature: badDomainSig })
      .expect(400);
    expect(res1.body.error).toBe('Invalid message format');

    const nonce2 = await agent
      .post('/api/login/wallet/nonce')
      .send({ walletAddress: wallet.address })
      .then(r => r.body.nonce);
    const badChainMsg = buildMessage(process.env.SIGNIN_DOMAIN!, wallet.address, nonce2, 2, ts);
    const badChainSig = await wallet.signMessage(badChainMsg);
    const res2 = await agent
      .post('/api/login/wallet')
      .send({ message: badChainMsg, signature: badChainSig })
      .expect(400);
    expect(res2.body.error).toBe('Invalid message format');
  });
});

describe('web3Auth utilities', () => {
  beforeEach(() => {
    mockRedis.store.clear();
  });

  it('parses valid EIP-4361 message', async () => {
    const { parseEip4361Message } = await import('../utils/web3Auth');
    const msg = buildMessage(
      process.env.SIGNIN_DOMAIN!,
      '0x000000000000000000000000000000000000dEaD',
      'n',
    );
    const parsed = parseEip4361Message(msg);
    expect(parsed.address).toBe(
      '0x000000000000000000000000000000000000dEaD',
    );
  });

  it('rejects invalid signature', async () => {
    const { verifyEip4361Signature } = await import('../utils/web3Auth');
    const wallet = Wallet.createRandom();
    const msg = buildMessage(process.env.SIGNIN_DOMAIN!, wallet.address, 'a');
    const sig = await wallet.signMessage('bad');
    await expect(verifyEip4361Signature(msg, sig)).rejects.toThrow();
  });

  it('prevents signature reuse', async () => {
    const { verifyEip4361Signature, _test } = await import('../utils/web3Auth');
    _test.memSigs.clear();
    const wallet = Wallet.createRandom();
    const msg = buildMessage(process.env.SIGNIN_DOMAIN!, wallet.address, 'a');
    const sig = await wallet.signMessage(msg);
    await verifyEip4361Signature(msg, sig);
    await expect(verifyEip4361Signature(msg, sig)).rejects.toThrow();
  });
});
