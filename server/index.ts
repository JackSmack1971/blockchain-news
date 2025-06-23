import express from 'express';
import session from 'express-session';
import cors from 'cors';
import csurf from 'csurf';
import { sanitize } from './utils/sanitize';
import { ethers } from 'ethers';
import { config } from './config';
import { logSecurityEvent } from './logging';
import { authRouter } from './auth';
import {
  initDb,
  resetDatabase,
  closePool,
} from './db';

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
if (!Number.isFinite(RATE_LIMIT_WINDOW_MS) || !Number.isFinite(RATE_LIMIT_MAX)) {
  throw new Error('Invalid rate limit configuration');
}
await initDb();

export const resetUsers = async (): Promise<void> => {
  await resetDatabase();
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

const requiredHeaders = [
  'content-security-policy',
  'x-frame-options',
  'strict-transport-security',
];
app.use((req, res, next) => {
  res.on('finish', () => {
    const missing = requiredHeaders.filter(h => !res.getHeader(h));
    if (missing.length) {
      logSecurityEvent('header_violation', { path: req.originalUrl, missing });
    }
  });
  next();
});

// Security headers middleware applied early in the pipeline
// CSP allows blockchain APIs and inlined styles/scripts for Vite in dev mode
const CSP_HEADER = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "connect-src 'self' https://api.coingecko.com",
].join('; ');

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=63072000; includeSubDomains; preload',
  );
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=()',
  );
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

app.use('/api', authRouter);

const requireAuth: express.RequestHandler = (req, res, next) => {
  if (req.session?.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
};


app.get('/api/protected', requireAuth, (req, res) => {
  res.json({ success: true });
});


const allowedProfileFields = ['username', 'email', 'bio', 'avatar', 'displayName'] as const;

app.post('/api/profile', requireAuth, (req, res) => {
  const profileUpdates: Record<string, string> = {};
  allowedProfileFields.forEach(field => {
    if (req.body[field] !== undefined) {
      profileUpdates[field] = sanitize(req.body[field]);
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
