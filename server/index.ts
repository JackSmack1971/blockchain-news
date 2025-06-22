import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import csurf from 'csurf';
import dotenv from 'dotenv';
import { loginSchema, registerSchema } from '../src/lib/validators';

dotenv.config();

const SESSION_SECRET = process.env.SESSION_SECRET as string;
if (!SESSION_SECRET) {
  throw new Error('SESSION_SECRET is required');
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

export const app = express();
app.use(express.json());
const isProd = process.env.NODE_ENV === 'production';
app.use(
  session({
    name: 'sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: isProd, sameSite: 'lax' },
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

const requireAuth: express.RequestHandler = (req, res, next) => {
  if (req.session?.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
};

app.post('/api/register', async (req, res) => {
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

app.post('/api/login', async (req, res) => {
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

app.post('/api/login/wallet', (req, res) => {
  const { walletAddress } = req.body as { walletAddress: string };
  if (!walletAddress) return res.status(400).json({ error: 'Wallet required' });
  const user: User = {
    id: crypto.randomUUID(),
    username: `wallet_${walletAddress.slice(0, 6)}`,
    email: '',
    passwordHash: '',
    walletAddress,
  };
  req.session.user = sanitize(user);
  res.json(sanitize(user));
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
  req.session.user = req.body.user;
  res.status(204).end();
});

app.delete('/api/token', (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

app.get('/api/protected', requireAuth, (req, res) => {
  res.json({ success: true });
});

app.post('/api/profile', requireAuth, (req, res) => {
  Object.assign(req.session.user, req.body);
  res.json({ success: true });
});

if (require.main === module) {
  app.listen(3001, () => console.log('server running on 3001'));
}
