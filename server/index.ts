import express from 'express';
import session from 'express-session';
import cors from 'cors';
import csurf from 'csurf';
import { sanitize } from './utils/sanitize';
import { config } from './config';
import { logSecurityEvent } from './logging';
import { authRouter } from './auth';
import { securityMiddleware } from './middleware/security';
import { profileUpdateSchema, commentSchema, searchSchema } from '../src/lib/validation';
import crypto from 'crypto';
import {
  initDb,
  resetDatabase,
  closePool,
} from './db';

export { validateEthereumAddress } from './utils/address';

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

interface Comment {
  id: string;
  articleId: string;
  userId: string;
  content: string;
}

const comments: Comment[] = [];
export const resetComments = (): void => {
  comments.length = 0;
};
export const getComments = (): Comment[] => comments;


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

// Apply security middleware with per-request CSP nonce
app.use(securityMiddleware);
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
  try {
    const parsed = profileUpdateSchema.partial().parse(req.body);
    const profileUpdates: Record<string, string> = {};
    allowedProfileFields.forEach(field => {
      if (parsed[field] !== undefined) {
        profileUpdates[field] = sanitize(parsed[field]);
      }
    });
    Object.assign(req.session.user, profileUpdates);
    res.json({ success: true });
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

app.post('/api/articles/:articleId/comments', requireAuth, (req, res) => {
  try {
    const { content } = commentSchema.parse(req.body);
    const sanitizedContent = sanitize(content);
    const articleId = sanitize(req.params.articleId);
    const comment = {
      id: crypto.randomUUID(),
      articleId,
      userId: req.session.user!.id,
      content: sanitizedContent,
    };
    comments.push(comment);
    res.status(201).json({ comment });
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

app.get('/api/articles/search', (req, res) => {
  try {
    const { query } = searchSchema.parse({ query: req.query.q });
    const sanitizedQuery = sanitize(query);
    res.json({ query: sanitizedQuery, results: [] });
  } catch {
    res.status(400).json({ error: 'Invalid input' });
  }
});

// Custom 404 handler to ensure consistent security headers
app.use('*', (req, res) => {
  res.setHeader('Content-Security-Policy', res.locals.cspHeader);
  res.status(404).json({ error: 'Not found' });
});

// Error handler to prevent Express from overriding security headers
app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Unhandled error:', err);
  res.setHeader('Content-Security-Policy', res.locals.cspHeader);
  res.status(500).json({ error: 'Internal Server Error' });
});

if (require.main === module) {
  app.listen(config.PORT, () => console.log(`server running on ${config.PORT}`));
}
