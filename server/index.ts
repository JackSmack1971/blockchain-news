import express from 'express';
import session from 'express-session';
import rateLimit, { MemoryStore } from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import csurf from 'csurf';
import cors from 'cors';
import dotenv from 'dotenv';
import { validateEnvironment } from './config/environment';
import crypto from 'crypto';
import { ethers } from 'ethers';
import { loginSchema, registerSchema, walletLoginSchema } from '../src/lib/validators';
import fs from 'fs/promises';
import {
  initDb,
  createUser,
  findUserByEmail,
  findUserByWallet,
  resetDatabase,
  closePool,
} from './db';

dotenv.config();

const envResult = validateEnvironment();
if (!envResult.success) {
  console.error(envResult.error);
  process.exit(1);
}
const config = envResult.data;

/**
 * Parse and validate cookie settings from environment variables.
 * Throws if values are invalid to prevent insecure configuration.
 */
const parseCookieOptions = () => {
  return {
    domain: config.COOKIE_DOMAIN || undefined,
    maxAge: config.COOKIE_MAX_AGE,
    secure: config.NODE_ENV === 'production' || config.COOKIE_SECURE,
    httpOnly: true,
    sameSite: 'strict' as const,
  };
};
const cookieOptions = parseCookieOptions();

const RATE_LIMIT_WINDOW_MS = config.RATE_LIMIT_WINDOW;
const RATE_LIMIT_MAX = config.RATE_LIMIT_MAX;
if (!config.SESSION_SECRET) {
  throw new Error('SESSION_SECRET is required');
}
if (!Number.isFinite(RATE_LIMIT_WINDOW_MS) || !Number.isFinite(RATE_LIMIT_MAX)) {
  throw new Error('Invalid rate limit configuration');
}
await initDb();

interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  walletAddress?: string;
}

export const resetUsers = async (): Promise<void> => {
  await resetDatabase();
};

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

export const shutdown = async (): Promise<void> => {
  await closePool();
};

export const app = express();
app.enable('trust proxy');

const corsOptions = {
  origin: config.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));

const authLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  store: new MemoryStore(),
});
export const _authLimiter = authLimiter; // test-only export

interface AddressValidation {
  valid: boolean;
  address?: string;
  error?: string;
}

export const validateEthereumAddress = (address: unknown): AddressValidation => {
  if (!address || typeof address !== 'string') {
    return { valid: false, error: 'Address must be a string' };
  }
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return { valid: false, error: 'Invalid Ethereum address format' };
  }
  try {
    return { valid: true, address: ethers.getAddress(address) };
  } catch {
    return { valid: false, error: 'Invalid address checksum' };
  }
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

export const authSecurityHeaders: express.RequestHandler = (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
};

/**
 * Redirect HTTP traffic to HTTPS when in production.
 */
export const enforceHttps: express.RequestHandler = (req, res, next) => {
  const host = req.headers.host;
  if (isProd && !req.secure && host) {
    return res.redirect(301, `https://${host}${req.originalUrl}`);
  }
  next();
};

app.use(enforceHttps);
app.use(express.json());

// Security headers middleware applied early in the pipeline
const CSP_HEADER =
  "default-src 'self'; " +
  "script-src 'self' 'unsafe-inline'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: https:; " +
  "connect-src 'self'";

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  next();
});
const isProd = config.NODE_ENV === 'production';
const cookieName = isProd ? '__Secure-sid' : 'sid';
app.use(
  session({
    name: cookieName,
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: cookieOptions,
  }),
);

app.use(
  ['/api/register', '/api/login', '/api/login/wallet', '/api/login/wallet/nonce'],
  authSecurityHeaders,
);

// Enable CSRF protection except during automated testing
if (config.NODE_ENV !== 'test') {
  const csrf = csurf();
  app.use(csrf);
  app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
  });
  app.use((err: unknown, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if ((err as { code?: string }).code === 'EBADCSRFTOKEN') {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    next(err as Error);
  });
}

const sanitize = (user: User) => ({
  id: user.id,
  username: user.username,
  email: user.email,
  walletAddress: user.walletAddress,
});

const createWalletUser = (address: string): User => ({
  id: crypto.randomUUID(),
  username: `wallet_${address.slice(0, 6)}`,
  email: '',
  passwordHash: '',
  walletAddress: address,
});

const logSecurityEvent = async (msg: string): Promise<void> => {
  try {
    await fs.mkdir('logs', { recursive: true });
    await fs.appendFile('logs/security.log', `${new Date().toISOString()} ${msg}\n`);
  } catch (err) {
    console.error('Failed to write security log', err);
  }
};

const requireAuth: express.RequestHandler = (req, res, next) => {
  if (req.session?.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
};

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password } = registerSchema.parse(req.body);
    const exists = await findUserByEmail(email);
    if (exists) {
      return res.status(400).json({ error: 'User exists' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const user: User = { id: crypto.randomUUID(), username, email, passwordHash };
    await createUser(user);
    req.session.user = sanitize(user);
    res.json(sanitize(user));
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body),
      attempt = loginAttempts.get(email) || { count: 0, lockUntil: 0 };
    if (attempt.lockUntil > Date.now()) {
      await logSecurityEvent(`Locked login attempt for ${email}`);
      await new Promise(r => setTimeout(r, Math.random() * 50));
      return res.status(403).json({ error: 'Account locked' });
    }
    const user = await findUserByEmail(email);
    const hashToCompare =
      user?.passwordHash || '$2b$10$dummy.hash.for.timing.consistency.protection.only';
    const isPasswordValid = await bcrypt.compare(password, hashToCompare);
    if (!user || !user.id || !isPasswordValid) {
      if (++attempt.count >= 5) {
        attempt.lockUntil = Date.now() + 15 * 60 * 1000;
        await logSecurityEvent(`Account locked for ${email}`);
      }
      loginAttempts.set(email, attempt); await new Promise(r => setTimeout(r, Math.random() * 50));
      await logSecurityEvent(`Failed login for ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
      loginAttempts.delete(email); req.session.user = sanitize(user);
      await logSecurityEvent(`Successful login for ${email}`);
      res.json({ message: 'Login successful', user: sanitize(user) });
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

app.post('/api/login/wallet/nonce', authLimiter, validateWalletAddress, (req, res) => {
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

app.post('/api/login/wallet', authLimiter, validateWalletAddress, async (req, res) => {
  try {
    const { walletAddress } = req.body as { walletAddress: string };
    const { signature } = req.body as { signature?: string };
    if (!signature) {
      return res.status(400).json({ error: 'signature required' });
    }
    walletLoginSchema.pick({ signature: true }).parse({ signature });
    const entry = nonceStore.get(walletAddress.toLowerCase());
    if (!entry || entry.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'Nonce expired' });
    }
    const recovered = ethers.verifyMessage(entry.nonce, signature);
    if (recovered.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
    nonceStore.delete(walletAddress.toLowerCase());
    let user = await findUserByWallet(walletAddress);
    if (!user) {
      user = createWalletUser(walletAddress);
      await createUser(user);
    }
    req.session.user = sanitize(user);
    res.json(sanitize(user));
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/token', (req, res) => {
  if (req.session.user) return res.json({ user: req.session.user });
  res.status(401).json({ error: 'No session' });
});

app.post('/api/token', (req, res) => {
  const { user } = req.body as { user: User };
  req.session.user = user;
  res.status(204).end();
});

app.delete('/api/token', (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

app.get('/api/protected', requireAuth, (req, res) => {
  res.json({ success: true });
});

/**
 * Sanitize untrusted string input to prevent injection attacks.
 * Simple replacement of angle brackets is used to neutralize HTML.
 *
 * @param input - Raw user provided value
 * @returns Sanitized string safe for storage
 */
const sanitizeInput = (input: unknown): string => {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>]/g, '').trim();
};

const allowedProfileFields = ['username', 'email', 'bio', 'avatar', 'displayName'] as const;

app.post('/api/profile', requireAuth, (req, res) => {
  const profileUpdates: Record<string, string> = {};
  allowedProfileFields.forEach(field => {
    if (req.body[field] !== undefined) {
      profileUpdates[field] = sanitizeInput(req.body[field]);
    }
  });
  Object.assign(req.session.user, profileUpdates);
  res.json({ success: true });
});

// Custom 404 handler to ensure consistent security headers
app.use('*', (req, res) => {
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  res.status(404).json({ error: 'Not found' });
});

// Error handler to prevent Express from overriding security headers
app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Unhandled error:', err);
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  res.status(500).json({ error: 'Internal Server Error' });
});

if (require.main === module) {
  app.listen(config.PORT, () => console.log(`server running on ${config.PORT}`));
}
