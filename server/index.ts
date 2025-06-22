import express from 'express';
import session from 'express-session';
import rateLimit, { MemoryStore } from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import csurf from 'csurf';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { ethers } from 'ethers';
import { loginSchema, registerSchema } from '../src/lib/validators';

dotenv.config();

const SESSION_SECRET = process.env.SESSION_SECRET as string;

/**
 * Parse and validate cookie settings from environment variables.
 * Throws if values are invalid to prevent insecure configuration.
 */
const parseCookieOptions = () => {
  const maxAgeEnv = parseInt(process.env.COOKIE_MAX_AGE || '', 10);
  const maxAge = Number.isFinite(maxAgeEnv)
    ? maxAgeEnv
    : 24 * 60 * 60 * 1000;
  if (maxAge <= 0) throw new Error('Invalid COOKIE_MAX_AGE');
  const domain = process.env.COOKIE_DOMAIN;
  if (domain && !/^[a-z0-9.-]+$/i.test(domain)) {
    throw new Error('Invalid COOKIE_DOMAIN');
  }
  return {
    domain: domain || undefined,
    maxAge,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict' as const,
  };
};
const cookieOptions = parseCookieOptions();

const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '5', 10);
if (!SESSION_SECRET) {
  throw new Error('SESSION_SECRET is required');
}
if (!Number.isFinite(RATE_LIMIT_WINDOW_MS) || !Number.isFinite(RATE_LIMIT_MAX)) {
  throw new Error('Invalid rate limit configuration');
}

interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  walletAddress?: string;
}

const users: User[] = [];
export const resetUsers = (): void => {
  users.length = 0;
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

export const app = express();
app.enable('trust proxy');

const authLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  store: new MemoryStore(),
});
export const _authLimiter = authLimiter; // test-only export

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
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https:; " +
      "connect-src 'self'"
  );
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  next();
});
const isProd = process.env.NODE_ENV === 'production';
const cookieName = isProd ? '__Secure-sid' : 'sid';
app.use(
  session({
    name: cookieName,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: cookieOptions,
  }),
);

// Enable CSRF protection except during automated testing
if (process.env.NODE_ENV !== 'test') {
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

const requireAuth: express.RequestHandler = (req, res, next) => {
  if (req.session?.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
};

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password } = registerSchema.parse(req.body);
    if (users.some(u => u.email === email)) {
      return res.status(400).json({ error: 'User exists' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const user: User = { id: crypto.randomUUID(), username, email, passwordHash };
    users.push(user);
    req.session.user = sanitize(user);
    res.json(sanitize(user));
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body);
    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.user = sanitize(user);
    res.json(sanitize(user));
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

app.post('/api/login/wallet/nonce', authLimiter, (req, res) => {
  try {
    const { walletAddress } = req.body as { walletAddress: string };
    if (!walletAddress) {
      return res.status(400).json({ error: 'Wallet required' });
    }
    let address: string;
    try {
      address = ethers.getAddress(walletAddress);
    } catch {
      return res.status(400).json({ error: 'Invalid address' });
    }
    const nonce = crypto.randomBytes(32).toString('hex');
    nonceStore.set(address.toLowerCase(), {
      nonce,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });
    res.json({ nonce });
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

app.post('/api/login/wallet', authLimiter, async (req, res) => {
  try {
    const { walletAddress, signature } = req.body as {
      walletAddress: string; signature: string };
    if (!walletAddress || !signature) {
      return res.status(400).json({ error: 'Wallet and signature required' });
    }
    let address: string;
    try {
      address = ethers.getAddress(walletAddress);
    } catch {
      return res.status(400).json({ error: 'Invalid address' });
    }
    const entry = nonceStore.get(address.toLowerCase());
    if (!entry || entry.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'Nonce expired' });
    }
    const recovered = ethers.verifyMessage(entry.nonce, signature);
    if (recovered.toLowerCase() !== address.toLowerCase()) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
    nonceStore.delete(address.toLowerCase());
    const user = createWalletUser(address);
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

if (require.main === module) {
  app.listen(3001, () => console.log('server running on 3001'));
}
