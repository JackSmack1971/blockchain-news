import express from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { validateEthereumAddress } from './utils/address';
import rateLimit, { MemoryStore } from 'express-rate-limit';
import { loginSchema, registerSchema } from '../src/lib/validation';
import { z } from 'zod';
import { verifyEip4361Signature, Web3AuthError } from './utils/web3Auth';
import { logSecurityEvent } from './logging';
import { createUser, findUserByEmail, findUserByWallet } from './db';

export const authSecurityHeaders: express.RequestHandler = (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
};


export const validateWalletAddress: express.RequestHandler = (req, res, next) => {
  const { walletAddress } = req.body as { walletAddress?: unknown };
  if (!walletAddress) {
    return res.status(400).json({ error: 'Wallet address is required' });
  }
  const validation = validateEthereumAddress(walletAddress);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }
  req.body.walletAddress = validation.address;
  next();
};

interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  walletAddress?: string;
}

interface NonceEntry {
  nonce: string;
  expiresAt: number;
}

const nonceStore = new Map<string, NonceEntry>();
export const _nonceStore = nonceStore; // test-only export
export const resetNonces = (): void => {
  nonceStore.clear();
};

interface AttemptInfo {
  count: number;
  lockUntil: number;
}
const loginAttempts = new Map<string, AttemptInfo>();
export const _loginAttempts = loginAttempts; // test-only export
export const resetLoginAttempts = (): void => {
  loginAttempts.clear();
};

export const authRouter = express.Router();

export const authLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW) || 60000,
  max: Number(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  store: new MemoryStore(),
  handler: (req, res) => {
    logSecurityEvent('rate_limit_exceeded', { ip: req.ip, path: req.originalUrl });
    res.status(429).json({ error: 'Too many requests' });
  },
});
export const _authLimiter = authLimiter; // test-only export

authRouter.use(['/register', '/login', '/login/wallet', '/login/wallet/nonce'], authSecurityHeaders, authLimiter);

authRouter.post('/register', async (req, res) => {
  try {
    const { username, email, password } = registerSchema.parse(req.body);
    const exists = await findUserByEmail(email);
    if (exists) {
      return res.status(400).json({ error: 'User exists' });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const user: User = { id: crypto.randomUUID(), username, email, passwordHash };
    await createUser(user);
    req.session.user = { id: user.id, username: user.username, email: user.email, walletAddress: user.walletAddress };
    res.json(req.session.user);
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

authRouter.post('/login', async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body),
      attempt = loginAttempts.get(email) || { count: 0, lockUntil: 0 };
    if (attempt.lockUntil > Date.now()) {
      await logSecurityEvent('account_locked', { email, ip: req.ip });
      await new Promise(r => setTimeout(r, Math.random() * 50));
      return res.status(403).json({ error: 'Account locked' });
    }
    const user = await findUserByEmail(email);
    const hashToCompare =
      user?.passwordHash || '$2a$12$4bFcCTq4crRNjgIHpqjWH.a0O5xtQjKhrFrG32JUfwre7O4ngmFOu';
    const isPasswordValid = await bcrypt.compare(password, hashToCompare);
    if (!user || !user.id || !isPasswordValid) {
      if (++attempt.count >= 5) {
        attempt.lockUntil = Date.now() + 15 * 60 * 1000;
        await logSecurityEvent('account_locked', { email, ip: req.ip });
      }
      loginAttempts.set(email, attempt);
      await new Promise(r => setTimeout(r, Math.random() * 50));
      await logSecurityEvent('failed_login', { email, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    loginAttempts.delete(email);
    req.session.user = { id: user.id, username: user.username, email: user.email, walletAddress: user.walletAddress };
    await logSecurityEvent('login_success', { email, ip: req.ip });
    res.json({ message: 'Login successful', user: req.session.user });
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

authRouter.post('/login/wallet/nonce', validateWalletAddress, (req, res) => {
  try {
    const { walletAddress } = req.body as { walletAddress: string };
    const nonce = crypto.randomBytes(32).toString('hex');
    nonceStore.set(walletAddress.toLowerCase(), {
      nonce,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });
    res.json({ nonce });
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

authRouter.post('/login/wallet', async (req, res) => {
  try {
    const { message, signature } = z
      .object({ message: z.string().min(1), signature: z.string().min(1) })
      .parse(req.body);
    const parsed = await verifyEip4361Signature(message, signature);
    const entry = nonceStore.get(parsed.address.toLowerCase());
    if (!entry || entry.expiresAt < Date.now() || entry.nonce !== parsed.nonce) {
      await logSecurityEvent('failed_login', { walletAddress: parsed.address, ip: req.ip, reason: 'nonce_expired' });
      return res.status(400).json({ error: 'Nonce expired' });
    }
    nonceStore.delete(parsed.address.toLowerCase());
    let user = await findUserByWallet(parsed.address);
    if (!user) {
      user = { id: crypto.randomUUID(), username: `wallet_${parsed.address.slice(0, 6)}`, email: '', passwordHash: '', walletAddress: parsed.address };
      await createUser(user);
    }
    req.session.user = { id: user.id, username: user.username, email: user.email, walletAddress: user.walletAddress };
    await logSecurityEvent('login_success', { walletAddress: parsed.address, ip: req.ip });
    res.json(req.session.user);
  } catch (err) {
    await logSecurityEvent('failed_login', { ip: req.ip, reason: (err as Error).message });
    const msg = err instanceof Web3AuthError ? err.message : 'Invalid input';
    res.status(400).json({ error: msg });
  }
});

authRouter.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

authRouter.get('/token', (req, res) => {
  if (req.session.user) return res.json({ user: req.session.user });
  res.status(401).json({ error: 'No session' });
});

authRouter.post('/token', (req, res) => {
  const { user } = req.body as { user: User };
  req.session.user = user;
  res.status(204).end();
});

authRouter.delete('/token', (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

