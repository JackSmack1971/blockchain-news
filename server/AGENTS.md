# Server-Side Security Implementation Guidelines

## Backend Architecture Overview

The `server/` directory contains the Express.js backend with comprehensive security implementations including authentication, session management, database operations, and API security.

### Key Files and Their Security Roles
- **`index.ts`**: Main application with security middleware, auth endpoints
- **`db.ts`**: PostgreSQL connection management and database security
- **`middleware/`**: Security headers, rate limiting, validation middleware
- **`routes/`**: API endpoints with authentication and authorization
- **`utils/`**: Cryptographic functions, input validation, security utilities

## Database Security (`db.ts`)

### Connection Management
```typescript
// Secure connection pooling configuration
import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});
```

### Critical Security Patterns
- **Parameterized Queries**: Always use `$1, $2` parameters, never string concatenation
- **Connection Cleanup**: Proper connection release in try/catch/finally blocks
- **Error Handling**: Never expose internal database errors to clients
- **Transaction Management**: Use transactions for multi-step operations

### Database Test Patterns
```typescript
// Proper test database isolation
import { beforeEach } from 'vitest';

beforeEach(async () => {
  await resetUsers();    // Clear user table
  resetNonces();         // Clear nonce cache
  resetLoginAttempts();  // Clear rate limit data
  _authLimiter.resetKey('::ffff:127.0.0.1');
  _authLimiter.resetKey('127.0.0.1');
});
```

### Common Database Issues and Solutions
- **Constraint Violations**: Ensure proper cleanup between tests
- **Connection Leaks**: Always release connections in finally blocks
- **Type Conflicts**: Drop and recreate types properly in test setup
- **Deadlocks**: Use consistent ordering for multi-table operations

## Authentication Security

### Web3 Wallet Authentication Flow
```typescript
// Secure nonce-based signature verification
interface WalletLoginRequest {
  walletAddress: string;
  signature: string;
  nonce: string;
}

// Critical validation steps:
1. Validate wallet address format (checksum)
2. Verify nonce exists and is recent
3. Cryptographically verify signature
4. Clear nonce after use (prevent replay)
5. Create secure session
```

### Email/Password Authentication
```typescript
import bcrypt from 'bcrypt';

// Constant-time operations to prevent timing attacks
const isValidLogin = await bcrypt.compare(password, hashedPassword);
const userExists = await findUserByEmail(email);

// Always take same amount of time regardless of user existence
if (!userExists || !isValidLogin) {
  // Simulate work to maintain constant timing
  await bcrypt.hash('dummy', 10);
  return res.status(401).json({ error: 'Invalid credentials' });
}
```

### Session Management Security
```typescript
import session from 'express-session';

// Secure session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict'
  }
}));

// Session property whitelist (prevent prototype pollution)
const ALLOWED_PROFILE_UPDATES = ['username', 'email', 'preferences'];
```

## Security Headers and Middleware

### Comprehensive Security Headers
```typescript
import express from 'express';

// Required security headers configuration
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  next();
});
```

### Rate Limiting Configuration
```typescript
import rateLimit from 'express-rate-limit';

// Authentication endpoint rate limiting
const authLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 5,
  message: 'Too many authentication attempts',
  standardHeaders: true,
  legacyHeaders: false,
});
```

## Input Validation and Sanitization

### Wallet Address Validation
```typescript
import { ethers } from 'ethers';

// Ethereum address validation with checksum
function isValidEthereumAddress(address: string): boolean {
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return false;
  
  try {
    // Implement EIP-55 checksum validation
    const checksumAddress = ethers.getAddress(address);
    return address === checksumAddress;
  } catch {
    return false;
  }
}
```

### API Request Validation
```typescript
import { body, validationResult } from 'express-validator';

// Comprehensive input validation middleware
const validateWalletLogin = [
  body('walletAddress')
    .isString()
    .custom(isValidEthereumAddress)
    .withMessage('Invalid wallet address'),
  body('signature')
    .isString()
    .isLength({ min: 132, max: 132 })
    .withMessage('Invalid signature format'),
  body('nonce')
    .isString()
    .isLength({ min: 32, max: 64 })
    .withMessage('Invalid nonce'),
];
```

## Error Handling and Logging

### Security Error Classes
```typescript
class DatabaseError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'DatabaseError';
    this.cause = cause;
  }
}

class ValidationError extends Error {
  constructor(message: string, public field?: string) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
  }
}
```

### Security Logging Patterns
```typescript
import { Request } from 'express';

// Security event logging
function logSecurityEvent(event: string, details: any, req: Request) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    details,
  };
  
  // Log to security log file
  securityLogger.info(logEntry);
  
  // Alert on critical events
  if (['failed_login', 'rate_limit_exceeded'].includes(event)) {
    alertingService.notify(logEntry);
  }
}
```

## API Endpoint Security Patterns

### Secure Route Implementation
```typescript
import express from 'express';

// Protected route pattern
app.post('/api/protected', 
  authLimiter,                    // Rate limiting
  requireAuthentication,          // Auth middleware
  validateInput,                  // Input validation
  async (req, res) => {
    try {
      // Secure implementation
      const result = await secureOperation(req.body);
      res.json({ success: true, data: result });
    } catch (error) {
      logSecurityEvent('operation_failed', { error: error.message }, req);
      res.status(500).json({ error: 'Operation failed' });
    }
  }
);
```

### CORS Configuration
```typescript
import cors from 'cors';

// Secure CORS for Web3 integration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
```

## Testing Security Implementation

### Security Test Structure
```typescript
import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';

describe('Security Tests', () => {
  beforeEach(async () => {
    // Reset all security state
    await resetUsers();
    resetNonces();
    resetLoginAttempts();
    _authLimiter.resetKey('::ffff:127.0.0.1');
  });

  it('rejects malicious input', async () => {
    const maliciousPayload = {
      username: '<script>alert("xss")</script>',
      __proto__: { isAdmin: true }
    };
    
    const res = await request(app)
      .post('/api/profile')
      .send(maliciousPayload);
      
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Invalid input');
  });
});
```

## Performance and Security Monitoring

### Metrics Collection
```typescript
// Security metrics tracking
const securityMetrics = {
  authAttempts: 0,
  rateLimitHits: 0,
  validationErrors: 0,
  sessionCreations: 0,
};

// Middleware to track metrics
app.use((req, res, next) => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    metricsCollector.record({
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration,
    });
  });
  
  next();
});
```

## Deployment Security Checklist

### Production Security Configuration
- [ ] `SESSION_SECRET` is cryptographically secure (32+ characters)
- [ ] Database connections use SSL in production
- [ ] Rate limiting properly configured for production load
- [ ] Security headers appropriate for production environment
- [ ] CORS configured for production frontend domain
- [ ] Error messages don't expose internal details
- [ ] All environment variables validated on startup
- [ ] Database migrations tested in staging environment

### Monitoring and Alerting Setup
- [ ] Security event logging configured
- [ ] Rate limit violation alerts enabled
- [ ] Authentication failure monitoring active
- [ ] Database performance monitoring in place
- [ ] Error tracking and reporting configured

## Troubleshooting Common Security Issues

### Authentication Problems
```bash
# Debug authentication flow
DEBUG=auth* npm start

# Test specific auth endpoint
curl -X POST http://localhost:3001/api/login/wallet \
  -H "Content-Type: application/json" \
  -d '{"walletAddress":"0x...","signature":"0x...","nonce":"..."}'
```

### Database Security Issues
```bash
# Check database connections
psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity;"

# Reset test database
npm run db:reset:test
```

### Rate Limiting Issues
```typescript
// Reset rate limiter for testing
_authLimiter.resetKey('127.0.0.1');
_authLimiter.resetKey('::ffff:127.0.0.1');
```

---

## Security Implementation Priorities

1. **CRITICAL**: Authentication and session security
2. **HIGH**: Input validation and XSS prevention
3. **MEDIUM**: Rate limiting and monitoring
4. **LOW**: Performance optimization and logging

Always prioritize security over convenience and follow the principle of least privilege for all access controls.
```

## server/__tests__/AGENTS.md

```markdown
# Security Testing Implementation Guidelines

## Testing Architecture Overview

The `server/__tests__/` directory contains comprehensive security tests focusing on authentication, authorization, input validation, and attack prevention. All tests use Vitest with Supertest for HTTP testing.

### Test File Organization
- **`securityAdditional.test.ts`**: Core security functionality tests
- **`securityHeaders.test.ts`**: Security header validation tests
- **`auth.test.ts`**: Authentication flow testing
- **`profile.test.ts`**: User profile and session security
- **Database-related tests**: Connection and transaction security

## Critical Test Environment Setup

### Database Test Isolation Pattern
```typescript
import { describe, it, beforeEach, expect } from 'vitest';
import request from 'supertest';

// CRITICAL: Proper test isolation setup
beforeEach(async () => {
  await resetUsers();           // Clear users table
  resetNonces();               // Clear nonce cache
  resetLoginAttempts();        // Clear rate limit data
  _authLimiter.resetKey('::ffff:127.0.0.1');  // Reset IPv6 rate limits
  _authLimiter.resetKey('127.0.0.1');         // Reset IPv4 rate limits
});
```

### Environment Variables for Testing
```typescript
// Required test environment configuration
process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key';
process.env.RATE_LIMIT_MAX = '10';
process.env.RATE_LIMIT_WINDOW = '1000';
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb';
```

### Test Module Import Pattern
```typescript
// Dynamic import after environment setup
const { app, resetUsers, resetNonces, resetLoginAttempts, _authLimiter } = await import('../index.ts');
```

## Security Test Categories

### 1. Authentication Security Tests

#### Web3 Wallet Authentication
```typescript
describe('Authentication Security', () => {
  it('rejects wallet login without signature', async () => {
    const res = await request(app)
      .post('/api/login/wallet')
      .send({ walletAddress: '0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d0' });
    
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('signature');  // CRITICAL: Must validate signature requirement
  });

  it('rejects invalid wallet addresses', async () => {
    const invalidAddresses = [
      'not-an-address',
      '0xinvalid',
      '0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d',     // Too short
      '0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d00',   // Too long
      '',
      null,
    ];
    
    for (const addr of invalidAddresses) {
      const res = await request(app)
        .post('/api/login/wallet')
        .send({ walletAddress: addr });
      expect(res.status).toBe(400);
    }
  });
});
```

#### Timing Attack Prevention
```typescript
it('performs constant-time login attempts', async () => {
  const agent = request.agent(app);
  
  // Register legitimate user
  await agent
    .post('/api/register')
    .send({ username: 'tim', email: 'tim@test.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
    .expect(200);
  
  // Test timing consistency
  const start1 = Date.now();
  await agent
    .post('/api/login')
    .send({ email: 'tim@test.com', password: 'wrong' });
  const time1 = Date.now() - start1;
  
  const start2 = Date.now();
  await agent
    .post('/api/login')
    .send({ email: 'bad@test.com', password: 'password123' });
  const time2 = Date.now() - start2;
  
  // Times should be within 50ms (constant-time validation)
  expect(Math.abs(time1 - time2)).toBeLessThan(50);
});
```

### 2. Session Security Tests

#### Session Property Manipulation Prevention
```typescript
describe('Session Security', () => {
  it('prevents session property manipulation', async () => {
    const agent = request.agent(app);
    
    // Register user
    await agent
      .post('/api/register')
      .send({ username: 'sally', email: 'sally@test.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200);
    
    // Attempt malicious profile update
    await agent
      .post('/api/profile')
      .send({ 
        username: 'newname',
        id: 'malicious',           // Should be ignored
        isAdmin: true,             // Should be ignored
        __proto__: { evil: true }  // Prototype pollution attempt
      })
      .expect(200);
    
    // Verify only allowed properties were updated
    const profile = await agent.get('/api/token').expect(200);
    expect(profile.body.user.username).toBe('newname');
    expect(profile.body.user.id).not.toBe('malicious');
    expect((profile.body.user as any).isAdmin).toBeUndefined();
  });
});
```

### 3. Security Headers Validation

#### Comprehensive Header Testing
```typescript
describe('Security Headers', () => {
  it('includes required security headers', async () => {
    const res = await request(app).get('/');
    
    // Core security headers
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-xss-protection']).toBe('1; mode=block');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    
    // CRITICAL: CSP configuration for React app
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
    
    // Additional security headers
    expect(res.headers['x-permitted-cross-domain-policies']).toBe('none');
    expect(res.headers['cross-origin-embedder-policy']).toBe('require-corp');
    expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
  });
});
```

### 4. Input Validation Security Tests

#### Malicious Input Testing
```typescript
describe('Input Validation', () => {
  it('sanitizes XSS attempts', async () => {
    const agent = request.agent(app);
    
    const xssPayloads = [
      '<script>alert("xss")</script>',
      'javascript:alert(1)',
      '<img src=x onerror=alert(1)>',
      '"><script>alert(document.cookie)</script>'
    ];
    
    for (const payload of xssPayloads) {
      const res = await agent
        .post('/api/register')
        .send({ 
          username: payload,
          email: 'test@test.com',
          password: 'Secret1!',
          confirmPassword: 'Secret1!'
        });
      
      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid input');
    }
  });
  
  it('prevents SQL injection attempts', async () => {
    const sqlPayloads = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "admin'--",
      "' UNION SELECT * FROM users --"
    ];
    
    for (const payload of sqlPayloads) {
      const res = await request(app)
        .post('/api/login')
        .send({ email: payload, password: 'password' });
      
      expect(res.status).toBe(400);
    }
  });
});
```

## Database Testing Patterns

### Database Error Handling Tests
```typescript
describe('Database Security', () => {
  it('handles database errors securely', async () => {
    // Test with malformed database operations
    const res = await request(app)
      .post('/api/register')
      .send({ 
        username: 'test',
        email: 'invalid-email-format',
        password: 'weak',
        confirmPassword: 'different'
      });
    
    expect(res.status).toBe(400);
    // Should not expose internal database errors
    expect(res.body.error).not.toContain('pg_');
    expect(res.body.error).not.toContain('postgres');
  });
  
  it('prevents concurrent user creation', async () => {
    const userData = {
      username: 'duplicate',
      email: 'duplicate@test.com',
      password: 'Secret1!',
      confirmPassword: 'Secret1!'
    };
    
    // Attempt concurrent registrations
    const [res1, res2] = await Promise.all([
      request(app).post('/api/register').send(userData),
      request(app).post('/api/register').send(userData)
    ]);
    
    // Only one should succeed
    const successCount = [res1, res2].filter(res => res.status === 200).length;
    expect(successCount).toBe(1);
  });
});
```

## Rate Limiting Tests

### Authentication Rate Limiting
```typescript
describe('Rate Limiting', () => {
  it('enforces rate limits on authentication endpoints', async () => {
    const attempts = [];
    
    // Exceed rate limit
    for (let i = 0; i < 12; i++) {
      attempts.push(
        request(app)
          .post('/api/login')
          .send({ email: 'test@test.com', password: 'wrong' })
      );
    }
    
    const responses = await Promise.all(attempts);
    const rateLimitedResponses = responses.filter(res => res.status === 429);
    
    expect(rateLimitedResponses.length).toBeGreaterThan(0);
  });
  
  it('rate limits are per-IP', async () => {
    // Test with different source IPs (requires proper test setup)
    const res = await request(app)
      .post('/api/login')
      .set('X-Forwarded-For', '192.168.1.100')
      .send({ email: 'test@test.com', password: 'wrong' });
    
    expect(res.status).not.toBe(429); // Should not be rate limited
  });
});
```

## Performance Security Tests

### DoS Prevention Tests
```typescript
describe('DoS Prevention', () => {
  it('limits request payload size', async () => {
    const largePayload = 'x'.repeat(1024 * 1024); // 1MB string
    
    const res = await request(app)
      .post('/api/register')
      .send({ 
        username: largePayload,
        email: 'test@test.com',
        password: 'Secret1!',
        confirmPassword: 'Secret1!'
      });
    
    expect(res.status).toBe(413); // Payload too large
  });
  
  it('handles high concurrent load', async () => {
    const requests = Array(100).fill(null).map(() =>
      request(app).get('/api/health')
    );
    
    const responses = await Promise.all(requests);
    const successCount = responses.filter(res => res.status === 200).length;
    
    expect(successCount).toBeGreaterThan(90); // 90% success rate minimum
  });
});
```

## Test Execution and Debugging

### Running Security Tests
```bash
# Run all security tests
pnpm run test:security

# Run specific security test file
pnpm vitest run server/__tests__/securityAdditional.test.ts

# Run with verbose output
pnpm vitest run server/__tests__/securityAdditional.test.ts --reporter=verbose

# Run specific test case
pnpm vitest run -t "rejects wallet login without signature"

# Debug mode with full logs
DEBUG=* pnpm vitest run server/__tests__/securityAdditional.test.ts
```

### Test Database Management
```bash
# Reset test database
psql $DATABASE_URL -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# Check database connections
psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'appdb';"

# Manual cleanup if tests fail
psql $DATABASE_URL -c "TRUNCATE users, sessions, nonces RESTART IDENTITY CASCADE;"
```

## Common Test Issues and Solutions

### Database Connection Issues
```typescript
import { afterAll, afterEach } from 'vitest';

// Solution: Proper connection cleanup in tests
afterAll(async () => {
  await pool.end(); // Close all database connections
});

// Solution: Wait for operations to complete
afterEach(async () => {
  await new Promise(resolve => setTimeout(resolve, 100));
});
```

### Race Condition Prevention
```typescript
// Solution: Sequential test execution for database operations
describe('Database Operations', () => {
  // Use async/await to ensure proper sequencing
  it('sequential operation test', async () => {
    await operation1();
    await operation2();
    await operation3();
  });
});
```

### Rate Limiter State Issues
```typescript
// Solution: Proper rate limiter reset
beforeEach(() => {
  // Reset all possible IP formats
  _authLimiter.resetKey('127.0.0.1');
  _authLimiter.resetKey('::1');
  _authLimiter.resetKey('::ffff:127.0.0.1');
});
```

## Test Coverage Requirements

### Security Test Coverage Checklist
- [ ] Authentication flows (email + Web3)
- [ ] Authorization and access control
- [ ] Input validation and sanitization
- [ ] Session management security
- [ ] Rate limiting effectiveness
- [ ] Security headers validation
- [ ] Database security and isolation
- [ ] Error handling security
- [ ] XSS and injection prevention
- [ ] DoS attack prevention

### Performance Benchmarks
- Authentication response time: < 200ms
- Database operations: < 100ms
- Rate limiting decision: < 10ms
- Session validation: < 50ms

---

## Security Testing Best Practices

1. **Isolation**: Each test should be completely independent
2. **Realistic Data**: Use realistic attack vectors and payloads
3. **Edge Cases**: Test boundary conditions and error scenarios
4. **Performance**: Include timing and load testing
5. **Documentation**: Document security assumptions and test rationale

Remember: Security tests should fail safely and provide clear diagnostic information when issues are detected.
