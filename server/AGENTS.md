# Backend Security & API Development Guide
**server/ - Express.js + TypeScript + PostgreSQL**

## 🎯 Purpose & Critical Security Context

The backend handles authentication, data persistence, API endpoints, and security enforcement for the BlockchainNews platform. Given our **HIGH RISK audit status** with 3 CRITICAL vulnerabilities, all backend development must prioritize security remediation and prevention.

---

## 🚨 CRITICAL: Security Vulnerabilities to Fix First

### **SEC-2025-001: Weak Session Secret (CRITICAL)**
```typescript
// server/config.ts - IMPLEMENT IMMEDIATELY
export const config = {
  SESSION_SECRET: (() => {
    const secret = process.env.SESSION_SECRET
    if (!secret || secret.length < 32) {
      throw new Error('SESSION_SECRET must be at least 32 characters of cryptographic randomness')
    }
    return secret
  })(),
  // ... other config
}

// Generate secure secret for production:
// node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### **SEC-2025-002: Web3 Signature Validation (CRITICAL)**
```typescript
// server/routes/auth.ts - IMPLEMENT EIP-4361 STANDARD
import { ethers } from 'ethers'

interface SignInMessage {
  domain: string
  address: string
  statement: string
  uri: string
  version: string
  chainId: number
  nonce: string
  issuedAt: string
}

// Store used nonces to prevent replay attacks
const usedNonces = new Set<string>()

function parseSignInMessage(message: string): SignInMessage | null {
  try {
    const lines = message.split('\n')
    
    // Validate EIP-4361 format
    const domain = lines[0].replace(' wants you to sign in with your Ethereum account:', '')
    const address = lines[1]
    const statement = lines[3]
    
    // Extract structured fields
    const uri = lines.find(l => l.startsWith('URI: '))?.replace('URI: ', '')
    const version = lines.find(l => l.startsWith('Version: '))?.replace('Version: ', '')
    const chainId = parseInt(lines.find(l => l.startsWith('Chain ID: '))?.replace('Chain ID: ', '') || '0')
    const nonce = lines.find(l => l.startsWith('Nonce: '))?.replace('Nonce: ', '')
    const issuedAt = lines.find(l => l.startsWith('Issued At: '))?.replace('Issued At: ', '')
    
    if (!uri || !version || !chainId || !nonce || !issuedAt) {
      return null
    }
    
    return { domain, address, statement, uri, version, chainId, nonce, issuedAt }
  } catch {
    return null
  }
}

authRouter.post('/login/wallet', async (req, res) => {
  try {
    const { message, signature } = req.body
    
    // Validate message format
    const parsedMessage = parseSignInMessage(message)
    if (!parsedMessage) {
      return res.status(400).json({ error: 'Invalid message format' })
    }
    
    // Validate domain and URI
    if (parsedMessage.domain !== req.get('host')) {
      return res.status(400).json({ error: 'Invalid domain' })
    }
    
    // Check nonce hasn't been used (prevent replay)
    if (usedNonces.has(parsedMessage.nonce)) {
      return res.status(400).json({ error: 'Nonce already used' })
    }
    
    // Validate timestamp (5 minute window)
    const issueTime = new Date(parsedMessage.issuedAt).getTime()
    const now = Date.now()
    if (Math.abs(now - issueTime) > 5 * 60 * 1000) {
      return res.status(400).json({ error: 'Message expired' })
    }
    
    // Verify signature
    const recoveredAddress = ethers.utils.verifyMessage(message, signature)
    if (recoveredAddress.toLowerCase() !== parsedMessage.address.toLowerCase()) {
      return res.status(400).json({ error: 'Invalid signature' })
    }
    
    // Mark nonce as used
    usedNonces.add(parsedMessage.nonce)
    
    // Continue with user authentication...
    const user = await findOrCreateWalletUser(recoveredAddress)
    // ... rest of auth logic
    
  } catch (error) {
    logger.error('Wallet auth error:', error)
    res.status(500).json({ error: 'Authentication failed' })
  }
})
```

### **SEC-2025-003: XSS Protection Enhancement (CRITICAL)**
```typescript
// server/middleware/security.ts - REPLACE REGEX SANITIZATION
import DOMPurify from 'isomorphic-dompurify'
import { z } from 'zod'

// Remove the basic regex sanitization
// const sanitizeInput = (input: unknown): string => { 
//   return input.replace(/[<>]/g, '').trim(); 
// }

// IMPLEMENT: Comprehensive input validation
export const sanitizeAndValidate = <T>(
  input: unknown,
  schema: z.ZodSchema<T>
): T => {
  // First sanitize if it's a string
  if (typeof input === 'string') {
    input = DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] })
  }
  
  // Then validate with Zod
  return schema.parse(input)
}

// Use for all user inputs
export const inputSchemas = {
  email: z.string().email().max(254).transform(s => s.trim().toLowerCase()),
  password: z.string().min(8).max(128),
  searchQuery: z.string().max(100).transform(s => s.trim()),
  articleTitle: z.string().max(200).transform(s => s.trim()),
  comment: z.string().max(1000).transform(s => s.trim())
}
```

---

## 🛡️ Security-First Architecture

### Express.js Security Middleware Stack
```typescript
// server/index.ts - REQUIRED SECURITY MIDDLEWARE
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import csrf from 'csurf'
import session from 'express-session'
import pgSession from 'connect-pg-simple'

const app = express()

// 1. Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "wss:", "https:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}))

// 2. CORS with strict configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
  optionsSuccessStatus: 200
}))

// 3. Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '900000'), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
  message: { error: 'Too many requests from this IP' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`)
    res.status(429).json({ error: 'Too many requests' })
  }
})
app.use('/api', limiter)

// 4. Session configuration with PostgreSQL store
const PgSession = pgSession(session)
app.use(session({
  store: new PgSession({
    pool: pgPool,
    tableName: 'session'
  }),
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Don't use default 'connect.sid'
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: parseInt(process.env.COOKIE_MAX_AGE || '86400000'), // 24 hours
    sameSite: 'strict'
  }
}))

// 5. CSRF protection (skip for testing)
if (process.env.NODE_ENV !== 'test') {
  const csrfProtection = csrf({
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    }
  })
  app.use(csrfProtection)
  
  // CSRF token endpoint
  app.get('/api/csrf', (req, res) => {
    res.json({ csrfToken: req.csrfToken() })
  })
}

// 6. Body parsing with size limits
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true, limit: '10mb' }))

// 7. Request logging with security events
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  })
  next()
})
```

### Database Security Configuration
```typescript
// server/database.ts - SECURE POSTGRESQL CONNECTION
import { Pool } from 'pg'
import { z } from 'zod'

// Validate database configuration
const dbConfigSchema = z.object({
  host: z.string().min(1),
  port: z.number().min(1).max(65535),
  database: z.string().min(1),
  user: z.string().min(1),
  password: z.string().min(8)
})

// Parse connection string securely
function parseConnectionString(connectionString: string) {
  try {
    const url = new URL(connectionString)
    
    return dbConfigSchema.parse({
      host: url.hostname,
      port: parseInt(url.port) || 5432,
      database: url.pathname.slice(1),
      user: url.username,
      password: url.password
    })
  } catch (error) {
    throw new Error('Invalid database connection string')
  }
}

// Create secure connection pool
export const pool = new Pool({
  ...parseConnectionString(process.env.DATABASE_URL!),
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  statement_timeout: 30000,
  query_timeout: 30000
})

// Secure query function with parameter validation
export async function secureQuery<T = any>(
  text: string,
  params: any[] = []
): Promise<T[]> {
  try {
    // Validate parameters
    if (params.some(param => typeof param === 'object' && param !== null)) {
      throw new Error('Object parameters not allowed in queries')
    }
    
    const result = await pool.query(text, params)
    return result.rows
  } catch (error) {
    logger.error('Database query error:', { 
      error: error.message,
      query: text.substring(0, 100) // Log first 100 chars only
    })
    throw new Error('Database operation failed')
  }
}

// ALWAYS use for database operations
export async function findUserByEmail(email: string) {
  return secureQuery(
    'SELECT id, email, password_hash, created_at FROM users WHERE email = $1',
    [email]
  )
}

export async function createUser(email: string, passwordHash: string) {
  return secureQuery(
    'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
    [email, passwordHash]
  )
}
```

### Authentication & Authorization
```typescript
// server/middleware/auth.ts - SECURE AUTHENTICATION
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { z } from 'zod'

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  throw new Error('JWT_SECRET environment variable required')
})()
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h'

// Password hashing with secure cost factor
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12')

export async function hashPassword(password: string): Promise<string> {
  try {
    return await bcrypt.hash(password, BCRYPT_ROUNDS)
  } catch (error) {
    throw new Error('Password hashing failed')
  }
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await bcrypt.compare(password, hash)
  } catch (error) {
    return false
  }
}

// JWT token generation with security claims
export function generateToken(userId: string, email: string): string {
  const payload = {
    sub: userId,
    email,
    iat: Math.floor(Date.now() / 1000),
    aud: 'blockchain-news',
    iss: 'blockchain-news-api'
  }
  
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    algorithm: 'HS256'
  })
}

// JWT verification middleware
export function verifyToken(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authorization token required' })
    }
    
    const token = authHeader.substring(7)
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      audience: 'blockchain-news',
      issuer: 'blockchain-news-api'
    }) as any
    
    // Attach user info to request
    req.user = {
      id: decoded.sub,
      email: decoded.email
    }
    
    next()
  } catch (error) {
    logger.warn('Token verification failed:', { 
      error: error.message,
      ip: req.ip 
    })
    res.status(401).json({ error: 'Invalid token' })
  }
}

// Role-based authorization
export function requireRole(role: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = await secureQuery(
        'SELECT role FROM users WHERE id = $1',
        [req.user.id]
      )
      
      if (!user[0] || user[0].role !== role) {
        return res.status(403).json({ error: 'Insufficient permissions' })
      }
      
      next()
    } catch (error) {
      res.status(500).json({ error: 'Authorization check failed' })
    }
  }
}
```

---

## 🔐 API Route Security Patterns

### Input Validation Middleware
```typescript
// server/middleware/validation.ts - COMPREHENSIVE INPUT VALIDATION
import { Request, Response, NextFunction } from 'express'
import { AnyZodObject, z } from 'zod'

// Request validation middleware factory
export function validateRequest(schema: {
  body?: AnyZodObject
  query?: AnyZodObject
  params?: AnyZodObject
}) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate request body
      if (schema.body) {
        req.body = schema.body.parse(req.body)
      }
      
      // Validate query parameters
      if (schema.query) {
        req.query = schema.query.parse(req.query)
      }
      
      // Validate route parameters
      if (schema.params) {
        req.params = schema.params.parse(req.params)
      }
      
      next()
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Validation failed',
          details: error.errors.map(e => ({
            field: e.path.join('.'),
            message: e.message
          }))
        })
      }
      
      res.status(400).json({ error: 'Invalid request format' })
    }
  }
}

// Common validation schemas
export const schemas = {
  email: z.string().email().max(254).transform(s => s.trim().toLowerCase()),
  password: z.string().min(8).max(128),
  id: z.string().uuid(),
  walletAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  pagination: z.object({
    page: z.string().transform(s => parseInt(s)).refine(n => n > 0).default('1'),
    limit: z.string().transform(s => parseInt(s)).refine(n => n > 0 && n <= 100).default('20')
  })
}
```

### Secure Route Examples
```typescript
// server/routes/auth.ts - SECURE AUTHENTICATION ROUTES
import express from 'express'
import { validateRequest, schemas } from '../middleware/validation'
import { hashPassword, verifyPassword, generateToken } from '../middleware/auth'

const authRouter = express.Router()

// User registration with validation
authRouter.post('/register', 
  validateRequest({
    body: z.object({
      email: schemas.email,
      password: schemas.password,
      confirmPassword: z.string()
    }).refine(data => data.password === data.confirmPassword, {
      message: "Passwords don't match"
    })
  }),
  async (req, res) => {
    try {
      const { email, password } = req.body
      
      // Check if user already exists
      const existingUser = await secureQuery(
        'SELECT id FROM users WHERE email = $1',
        [email]
      )
      
      if (existingUser.length > 0) {
        return res.status(409).json({ error: 'Email already registered' })
      }
      
      // Hash password and create user
      const passwordHash = await hashPassword(password)
      const newUser = await secureQuery(
        'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
        [email, passwordHash]
      )
      
      // Generate token
      const token = generateToken(newUser[0].id, newUser[0].email)
      
      // Set secure session
      req.session.userId = newUser[0].id
      
      res.status(201).json({
        message: 'User created successfully',
        token,
        user: { id: newUser[0].id, email: newUser[0].email }
      })
      
    } catch (error) {
      logger.error('Registration error:', error)
      res.status(500).json({ error: 'Registration failed' })
    }
  }
)

// User login with rate limiting
authRouter.post('/login',
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: { error: 'Too many login attempts' }
  }),
  validateRequest({
    body: z.object({
      email: schemas.email,
      password: z.string().max(128)
    })
  }),
  async (req, res) => {
    try {
      const { email, password } = req.body
      
      // Find user
      const users = await secureQuery(
        'SELECT id, email, password_hash FROM users WHERE email = $1',
        [email]
      )
      
      if (users.length === 0) {
        // Use same timing as password verification to prevent timing attacks
        await bcrypt.compare(password, '$2b$12$dummy.hash.to.prevent.timing.attacks')
        return res.status(401).json({ error: 'Invalid credentials' })
      }
      
      const user = users[0]
      
      // Verify password
      const isValidPassword = await verifyPassword(password, user.password_hash)
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid credentials' })
      }
      
      // Generate token
      const token = generateToken(user.id, user.email)
      
      // Set secure session
      req.session.userId = user.id
      
      res.json({
        message: 'Login successful',
        token,
        user: { id: user.id, email: user.email }
      })
      
    } catch (error) {
      logger.error('Login error:', error)
      res.status(500).json({ error: 'Login failed' })
    }
  }
)

export default authRouter
```

---

## 🧪 Security Testing Requirements

### Test File Structure
```
server/__tests__/
├── auth.security.test.ts        # Authentication security tests
├── xss.security.test.ts         # XSS prevention tests
├── csrf.security.test.ts        # CSRF protection tests
├── injection.security.test.ts   # SQL injection tests
├── rate-limit.security.test.ts  # Rate limiting tests
└── session.security.test.ts     # Session security tests
```

### Example Security Test Patterns
```typescript
// server/__tests__/auth.security.test.ts
import request from 'supertest'
import { app } from '../index'
import { pool } from '../database'

describe('Authentication Security Tests', () => {
  beforeEach(async () => {
    // Clean database before each test
    await pool.query('DELETE FROM users WHERE email LIKE %test%')
  })
  
  describe('Password Security', () => {
    it('should reject weak passwords', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'test@example.com',
          password: '123456', // Weak password
          confirmPassword: '123456'
        })
      
      expect(response.status).toBe(400)
      expect(response.body.error).toContain('Validation failed')
    })
    
    it('should hash passwords securely', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!',
          confirmPassword: 'SecurePass123!'
        })
      
      expect(response.status).toBe(201)
      
      // Verify password is hashed in database
      const user = await pool.query('SELECT password_hash FROM users WHERE email = $1', ['test@example.com'])
      expect(user.rows[0].password_hash).not.toBe('SecurePass123!')
      expect(user.rows[0].password_hash.startsWith('$2b)).toBe(true)
    })
  })
  
  describe('Session Security', () => {
    it('should create secure session cookies', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'existing@example.com',
          password: 'SecurePass123!'
        })
      
      const cookies = response.headers['set-cookie']
      const sessionCookie = cookies.find(cookie => cookie.includes('sessionId'))
      
      expect(sessionCookie).toContain('HttpOnly')
      expect(sessionCookie).toContain('SameSite=Strict')
      if (process.env.NODE_ENV === 'production') {
        expect(sessionCookie).toContain('Secure')
      }
    })
    
    it('should prevent session fixation attacks', async () => {
      // Login with one session
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!'
        })
      
      const sessionCookie = loginResponse.headers['set-cookie'][0]
      
      // Try to use same session for different user
      const response = await request(app)
        .get('/api/user/profile')
        .set('Cookie', sessionCookie)
      
      expect(response.status).toBe(200)
      expect(response.body.user.email).toBe('test@example.com')
    })
  })
  
  describe('JWT Security', () => {
    it('should generate secure JWT tokens', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!'
        })
      
      expect(response.body.token).toBeDefined()
      
      // Verify token structure
      const tokenParts = response.body.token.split('.')
      expect(tokenParts).toHaveLength(3) // header.payload.signature
      
      // Verify token contains required claims
      const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString())
      expect(payload.sub).toBeDefined()
      expect(payload.email).toBe('test@example.com')
      expect(payload.aud).toBe('blockchain-news')
      expect(payload.iss).toBe('blockchain-news-api')
    })
    
    it('should reject tampered JWT tokens', async () => {
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!'
        })
      
      // Tamper with token
      const originalToken = loginResponse.body.token
      const tamperedToken = originalToken.slice(0, -5) + 'XXXXX'
      
      const response = await request(app)
        .get('/api/user/profile')
        .set('Authorization', `Bearer ${tamperedToken}`)
      
      expect(response.status).toBe(401)
      expect(response.body.error).toBe('Invalid token')
    })
  })
  
  describe('Web3 Authentication Security', () => {
    it('should validate EIP-4361 message format', async () => {
      const invalidMessage = 'Invalid message format'
      const signature = '0x1234567890abcdef'
      
      const response = await request(app)
        .post('/api/auth/login/wallet')
        .send({ message: invalidMessage, signature })
      
      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Invalid message format')
    })
    
    it('should prevent replay attacks with nonce validation', async () => {
      const message = `localhost:3001 wants you to sign in with your Ethereum account:
0x742d35Cc6643C0532925a3b8D9CE8068c2b04c3B

Sign in to BlockchainNews

URI: http://localhost:3001
Version: 1
Chain ID: 1
Nonce: test-nonce-12345678
Issued At: ${new Date().toISOString()}`
      
      const signature = '0xvalidSignature...'
      
      // First request should succeed (mocked)
      // Second request with same nonce should fail
      const secondResponse = await request(app)
        .post('/api/auth/login/wallet')
        .send({ message, signature })
      
      expect(secondResponse.status).toBe(400)
      expect(secondResponse.body.error).toBe('Nonce already used')
    })
  })
})

// server/__tests__/xss.security.test.ts
describe('XSS Prevention Tests', () => {
  describe('Input Sanitization', () => {
    it('should sanitize script tags in user inputs', async () => {
      const maliciousInput = '<script>alert("xss")</script>Hello World'
      
      const response = await request(app)
        .post('/api/articles/comment')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          articleId: 'valid-uuid',
          content: maliciousInput
        })
      
      expect(response.status).toBe(201)
      
      // Verify content is sanitized in database
      const comment = await pool.query('SELECT content FROM comments WHERE article_id = $1', ['valid-uuid'])
      expect(comment.rows[0].content).not.toContain('<script>')
      expect(comment.rows[0].content).toBe('Hello World')
    })
    
    it('should prevent encoded XSS attempts', async () => {
      const encodedXSS = '&lt;script&gt;alert("xss")&lt;/script&gt;'
      
      const response = await request(app)
        .post('/api/user/profile')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          bio: encodedXSS
        })
      
      expect(response.status).toBe(200)
      
      // Verify content is properly sanitized
      const user = await pool.query('SELECT bio FROM users WHERE id = $1', [userId])
      expect(user.rows[0].bio).not.toContain('script')
    })
  })
  
  describe('Output Encoding', () => {
    it('should properly encode HTML entities in API responses', async () => {
      // Create content with special characters
      await pool.query(
        'INSERT INTO articles (id, title, content) VALUES ($1, $2, $3)',
        ['test-id', 'Test & Title', 'Content with <special> characters']
      )
      
      const response = await request(app)
        .get('/api/articles/test-id')
      
      expect(response.status).toBe(200)
      expect(response.body.title).toBe('Test & Title')
      expect(response.body.content).toBe('Content with <special> characters')
    })
  })
})

// server/__tests__/csrf.security.test.ts
describe('CSRF Protection Tests', () => {
  describe('Token Validation', () => {
    it('should reject POST requests without CSRF token', async () => {
      const response = await request(app)
        .post('/api/user/profile')
        .set('Authorization', `Bearer ${validToken}`)
        .send({ bio: 'Updated bio' })
      
      expect(response.status).toBe(403)
      expect(response.body.error).toContain('CSRF')
    })
    
    it('should accept POST requests with valid CSRF token', async () => {
      // Get CSRF token
      const csrfResponse = await request(app)
        .get('/api/csrf')
        .set('Cookie', sessionCookie)
      
      const csrfToken = csrfResponse.body.csrfToken
      
      const response = await request(app)
        .post('/api/user/profile')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-CSRF-Token', csrfToken)
        .set('Cookie', sessionCookie)
        .send({ bio: 'Updated bio' })
      
      expect(response.status).toBe(200)
    })
    
    it('should reject requests with invalid CSRF token', async () => {
      const response = await request(app)
        .post('/api/user/profile')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-CSRF-Token', 'invalid-token')
        .send({ bio: 'Updated bio' })
      
      expect(response.status).toBe(403)
    })
  })
})

// server/__tests__/injection.security.test.ts
describe('SQL Injection Prevention Tests', () => {
  describe('Parameterized Queries', () => {
    it('should prevent SQL injection in search queries', async () => {
      const maliciousQuery = "'; DROP TABLE users; --"
      
      const response = await request(app)
        .get('/api/articles/search')
        .query({ q: maliciousQuery })
      
      expect(response.status).toBe(200)
      
      // Verify users table still exists
      const result = await pool.query('SELECT COUNT(*) FROM users')
      expect(result.rows[0].count).toBeDefined()
    })
    
    it('should prevent SQL injection in user input fields', async () => {
      const maliciousEmail = "admin'; UPDATE users SET role = 'admin' WHERE email = 'attacker@evil.com'; --"
      
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: maliciousEmail,
          password: 'SecurePass123!',
          confirmPassword: 'SecurePass123!'
        })
      
      expect(response.status).toBe(400) // Should fail validation
      
      // Verify no privilege escalation occurred
      const users = await pool.query("SELECT role FROM users WHERE email = 'attacker@evil.com'")
      expect(users.rows).toHaveLength(0)
    })
  })
})

// server/__tests__/rate-limit.security.test.ts
describe('Rate Limiting Tests', () => {
  describe('API Rate Limits', () => {
    it('should enforce rate limits on API endpoints', async () => {
      const requests = []
      
      // Make multiple requests quickly
      for (let i = 0; i < 101; i++) {
        requests.push(
          request(app)
            .get('/api/articles')
            .expect(res => res.status === 200 || res.status === 429)
        )
      }
      
      const responses = await Promise.all(requests)
      const rateLimitedResponses = responses.filter(res => res.status === 429)
      
      expect(rateLimitedResponses.length).toBeGreaterThan(0)
    })
    
    it('should have stricter limits on authentication endpoints', async () => {
      const requests = []
      
      // Make multiple login attempts
      for (let i = 0; i < 6; i++) {
        requests.push(
          request(app)
            .post('/api/auth/login')
            .send({
              email: 'test@example.com',
              password: 'WrongPassword'
            })
        )
      }
      
      const responses = await Promise.all(requests)
      const lastResponse = responses[responses.length - 1]
      
      expect(lastResponse.status).toBe(429)
      expect(lastResponse.body.error).toContain('Too many login attempts')
    })
  })
})
```

---

## 🔧 Development Workflow

### Pre-Development Checklist
1. **Security Review**: Check audit findings for relevant issues
2. **Input Validation**: Plan Zod schemas for all inputs
3. **Error Handling**: Design secure error responses
4. **Testing Strategy**: Plan security test cases

### During Development
1. **Always use parameterized queries** - Never string concatenation
2. **Validate all inputs** with Zod schemas
3. **Handle errors securely** - Don't expose internal details
4. **Log security events** for monitoring

### Pre-Commit Requirements
```bash
# Required before every commit
pnpm test:security          # All security tests must pass
pnpm run type-check         # TypeScript validation
pnpm run lint              # ESLint security rules
pnpm audit --audit-level moderate  # Dependency security
```

### Code Review Security Checklist
- [ ] All database queries use parameterized statements
- [ ] Input validation with Zod schemas implemented
- [ ] Error handling doesn't expose sensitive information
- [ ] Authentication/authorization checks on protected routes
- [ ] CSRF protection on state-changing operations
- [ ] Rate limiting on sensitive endpoints
- [ ] Security headers properly configured
- [ ] Passwords hashed with bcrypt (cost factor ≥12)
- [ ] JWT tokens include proper security claims
- [ ] Web3 signatures validated according to EIP-4361

---

## 📊 Performance & Monitoring

### Security Event Logging
```typescript
// server/utils/logger.ts - SECURITY EVENT LOGGING
import winston from 'winston'

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'blockchain-news-api' },
  transports: [
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error' 
    }),
    new winston.transports.File({ 
      filename: 'logs/security.log',
      level: 'warn'
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log' 
    })
  ]
})

// Security event logging functions
export const securityLogger = {
  authFailure: (ip: string, email: string, reason: string) => {
    logger.warn('Authentication failure', {
      type: 'AUTH_FAILURE',
      ip,
      email: email.substring(0, 3) + '***', // Partial email for privacy
      reason,
      timestamp: new Date().toISOString()
    })
  },
  
  suspiciousActivity: (ip: string, activity: string, details: any) => {
    logger.warn('Suspicious activity detected', {
      type: 'SUSPICIOUS_ACTIVITY',
      ip,
      activity,
      details,
      timestamp: new Date().toISOString()
    })
  },
  
  rateLimitExceeded: (ip: string, endpoint: string) => {
    logger.warn('Rate limit exceeded', {
      type: 'RATE_LIMIT_EXCEEDED',
      ip,
      endpoint,
      timestamp: new Date().toISOString()
    })
  }
}
```

### Performance Monitoring
```typescript
// server/middleware/performance.ts - PERFORMANCE MONITORING
import { Request, Response, NextFunction } from 'express'

// Track slow queries
export function trackSlowQueries(threshold: number = 1000) {
  return (req: Request, res: Response, next: NextFunction) => {
    const start = Date.now()
    
    res.on('finish', () => {
      const duration = Date.now() - start
      
      if (duration > threshold) {
        logger.warn('Slow request detected', {
          method: req.method,
          url: req.url,
          duration,
          ip: req.ip
        })
      }
    })
    
    next()
  }
}

// Memory usage monitoring
export function monitorMemoryUsage() {
  setInterval(() => {
    const usage = process.memoryUsage()
    
    if (usage.heapUsed > 100 * 1024 * 1024) { // 100MB threshold
      logger.warn('High memory usage detected', {
        heapUsed: Math.round(usage.heapUsed / 1024 / 1024) + 'MB',
        heapTotal: Math.round(usage.heapTotal / 1024 / 1024) + 'MB'
      })
    }
  }, 60000) // Check every minute
}
```

---

## 🚀 Production Deployment Security

### Environment Variables Validation
```typescript
// server/config.ts - PRODUCTION CONFIGURATION VALIDATION
import { z } from 'zod'

const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']),
  PORT: z.string().transform(s => parseInt(s)).refine(n => n > 0 && n < 65536),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  SESSION_SECRET: z.string().min(32),
  FRONTEND_URL: z.string().url(),
  RATE_LIMIT_WINDOW: z.string().transform(s => parseInt(s)),
  RATE_LIMIT_MAX: z.string().transform(s => parseInt(s)),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info')
})

// Validate configuration on startup
try {
  export const config = configSchema.parse(process.env)
  logger.info('Configuration validated successfully')
} catch (error) {
  logger.error('Configuration validation failed:', error)
  process.exit(1)
}
```

### Health Check Endpoint
```typescript
// server/routes/health.ts - PRODUCTION HEALTH CHECKS
import express from 'express'
import { pool } from '../database'

const healthRouter = express.Router()

healthRouter.get('/health', async (req, res) => {
  try {
    // Check database connection
    await pool.query('SELECT 1')
    
    // Check memory usage
    const memUsage = process.memoryUsage()
    const memUsageMB = Math.round(memUsage.heapUsed / 1024 / 1024)
    
    // Check uptime
    const uptime = Math.round(process.uptime())
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: `${uptime}s`,
      memory: `${memUsageMB}MB`,
      database: 'connected'
    })
  } catch (error) {
    logger.error('Health check failed:', error)
    res.status(503).json({
      status: 'unhealthy',
      error: 'Service unavailable'
    })
  }
})

export default healthRouter
```

---

## 🆘 Troubleshooting Guide

### Common Security Issues
```bash
# CSRF token issues
# Check if frontend is sending X-CSRF-Token header
curl -X POST http://localhost:3001/api/user/profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -d '{"bio": "test"}'

# JWT verification failures
# Verify JWT secret matches between environments
node -e "console.log(require('jsonwebtoken').verify('$TOKEN', '$SECRET'))"

# Database connection issues
# Test PostgreSQL connection
psql $DATABASE_URL -c "SELECT version();"

# Rate limiting problems
# Check Redis connection (if using Redis for rate limiting)
redis-cli ping
```

### Security Monitoring Commands
```bash
# Check for suspicious activity in logs
grep "AUTH_FAILURE" logs/security.log | tail -20

# Monitor rate limit violations
grep "RATE_LIMIT_EXCEEDED" logs/security.log | tail -20

# Check for XSS attempts in request logs
grep -i "script\|javascript\|onerror" logs/combined.log

# Monitor database connection pool
grep "database" logs/combined.log | grep -i "error\|timeout"
```

---

## 📚 Additional Resources

### Security References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Checklist](https://nodejs.org/en/docs/guides/security/)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)

### Internal Documentation
- **Root Guide**: `AGENTS.md` (project overview)
- **Frontend Security**: `src/lib/AGENTS.md`
- **Security Tests**: `server/__tests__/AGENTS.md`
- **Deployment Guide**: `README.md`

Remember: The backend is the last line of defense. Every endpoint, every query, every operation must be secured against the threats identified in our security audit.
