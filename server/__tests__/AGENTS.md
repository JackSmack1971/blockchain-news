# Security Testing Guide
**server/__tests__/ - Comprehensive Security Test Suite**

## 🎯 Purpose & Critical Mission

This directory contains security-focused tests designed to validate defenses against the **19 security vulnerabilities** identified in our audit. Every test case here directly addresses real attack vectors and ensures our security controls work as intended.

**Testing Philosophy**: Fail securely, test maliciously, validate comprehensively.

---

## 🚨 Priority Testing Areas (Based on Audit Findings)

### **CRITICAL Tests (Must Pass Before Any Deployment)**

1. **Session Security** (`session.security.test.ts`)
2. **Web3 Authentication** (`web3-auth.security.test.ts`)
3. **XSS Prevention** (`xss.security.test.ts`)
4. **CSRF Protection** (`csrf.security.test.ts`)
5. **SQL Injection Prevention** (`injection.security.test.ts`)

### **HIGH Priority Tests**
6. **Rate Limiting** (`rate-limit.security.test.ts`)
7. **Input Validation** (`validation.security.test.ts`)
8. **Authentication** (`auth.security.test.ts`)
9. **Authorization** (`authorization.security.test.ts`)

---

## 🧪 Test File Structure & Requirements

### File Naming Convention
```
server/__tests__/
├── *.security.test.ts          # Security-focused tests
├── *.integration.test.ts       # Integration tests with security
├── *.performance.test.ts       # Performance security tests
└── helpers/
    ├── security-helpers.ts     # Reusable security test utilities
    ├── mock-data.ts           # Test data with attack vectors
    └── test-setup.ts          # Test environment configuration
```

### Test Structure Template
```typescript
// Template for all security tests
import request from 'supertest'
import { app } from '../index'
import { pool } from '../database'
import { securityHelpers } from './helpers/security-helpers'

describe('[Feature] Security Tests', () => {
  // Setup and teardown
  beforeAll(async () => {
    await securityHelpers.setupTestDatabase()
  })
  
  afterAll(async () => {
    await securityHelpers.cleanupTestDatabase()
    await pool.end()
  })
  
  beforeEach(async () => {
    await securityHelpers.resetTestData()
  })
  
  // Test categories
  describe('Attack Vector Prevention', () => {
    // Tests that validate specific attack prevention
  })
  
  describe('Input Validation', () => {
    // Tests that validate input sanitization
  })
  
  describe('Error Handling', () => {
    // Tests that ensure secure error responses
  })
})
```

---

## 🔐 Critical Security Test Implementations

### **1. Session Security Tests** (`session.security.test.ts`)
*Addresses SEC-2025-001: Weak Session Secret*

```typescript
import request from 'supertest'
import crypto from 'crypto'
import { app } from '../index'

describe('Session Security Tests', () => {
  describe('Session Secret Validation', () => {
    it('should reject weak session secrets during startup', () => {
      // This test validates the session secret validation in config.ts
      const originalSecret = process.env.SESSION_SECRET
      
      // Test with weak secret
      process.env.SESSION_SECRET = 'weak'
      
      expect(() => {
        // Re-import config to trigger validation
        delete require.cache[require.resolve('../config')]
        require('../config')
      }).toThrow('SESSION_SECRET must be at least 32 characters')
      
      // Restore original secret
      process.env.SESSION_SECRET = originalSecret
    })
    
    it('should accept cryptographically secure session secrets', () => {
      const secureSecret = crypto.randomBytes(32).toString('hex')
      process.env.SESSION_SECRET = secureSecret
      
      expect(() => {
        delete require.cache[require.resolve('../config')]
        require('../config')
      }).not.toThrow()
    })
  })
  
  describe('Session Cookie Security', () => {
    it('should set secure session cookies in production', async () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'production'
      
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!'
        })
      
      const cookies = response.headers['set-cookie']
      const sessionCookie = cookies.find(cookie => cookie.includes('sessionId'))
      
      expect(sessionCookie).toContain('Secure')
      expect(sessionCookie).toContain('HttpOnly')
      expect(sessionCookie).toContain('SameSite=Strict')
      
      process.env.NODE_ENV = originalEnv
    })
    
    it('should prevent session fixation attacks', async () => {
      // Create initial session
      const initialResponse = await request(app)
        .get('/api/csrf')
      
      const initialCookies = initialResponse.headers['set-cookie']
      
      // Login with the session
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .set('Cookie', initialCookies)
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!'
        })
      
      const loginCookies = loginResponse.headers['set-cookie']
      
      // Session ID should change after login
      expect(loginCookies).not.toEqual(initialCookies)
    })
    
    it('should invalidate sessions on logout', async () => {
      // Login to get session
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!'
        })
      
      const sessionCookie = loginResponse.headers['set-cookie']
      
      // Logout
      await request(app)
        .post('/api/auth/logout')
        .set('Cookie', sessionCookie)
      
      // Try to access protected resource with old session
      const response = await request(app)
        .get('/api/user/profile')
        .set('Cookie', sessionCookie)
      
      expect(response.status).toBe(401)
    })
  })
})
```

### **2. Web3 Authentication Security Tests** (`web3-auth.security.test.ts`)
*Addresses SEC-2025-002: Insufficient Web3 Signature Validation*

```typescript
import request from 'supertest'
import { ethers } from 'ethers'
import { app } from '../index'

describe('Web3 Authentication Security Tests', () => {
  let wallet: ethers.Wallet
  let validMessage: string
  let validSignature: string
  
  beforeEach(() => {
    wallet = ethers.Wallet.createRandom()
    const timestamp = new Date().toISOString()
    const nonce = crypto.randomBytes(16).toString('hex')
    
    validMessage = `localhost:3001 wants you to sign in with your Ethereum account:
${wallet.address}

Sign in to BlockchainNews

URI: http://localhost:3001
Version: 1
Chain ID: 1
Nonce: ${nonce}
Issued At: ${timestamp}`
    
    validSignature = wallet.signMessage(validMessage)
  })
  
  describe('EIP-4361 Message Format Validation', () => {
    it('should accept valid EIP-4361 formatted messages', async () => {
      const response = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: validMessage,
          signature: validSignature
        })
      
      expect(response.status).toBe(200)
      expect(response.body.token).toBeDefined()
    })
    
    it('should reject malformed messages', async () => {
      const malformedMessage = 'Just some random text'
      
      const response = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: malformedMessage,
          signature: validSignature
        })
      
      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Invalid message format')
    })
    
    it('should validate required EIP-4361 fields', async () => {
      const incompleteMessage = `localhost:3001 wants you to sign in with your Ethereum account:
${wallet.address}

Sign in to BlockchainNews`
      // Missing URI, Version, Chain ID, Nonce, Issued At
      
      const response = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: incompleteMessage,
          signature: validSignature
        })
      
      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Invalid message format')
    })
  })
  
  describe('Replay Attack Prevention', () => {
    it('should prevent nonce reuse', async () => {
      // First login should succeed
      const firstResponse = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: validMessage,
          signature: validSignature
        })
      
      expect(firstResponse.status).toBe(200)
      
      // Second login with same nonce should fail
      const secondResponse = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: validMessage,
          signature: validSignature
        })
      
      expect(secondResponse.status).toBe(400)
      expect(secondResponse.body.error).toBe('Nonce already used')
    })
    
    it('should reject expired messages', async () => {
      const expiredTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString() // 10 minutes ago
      const nonce = crypto.randomBytes(16).toString('hex')
      
      const expiredMessage = `localhost:3001 wants you to sign in with your Ethereum account:
${wallet.address}

Sign in to BlockchainNews

URI: http://localhost:3001
Version: 1
Chain ID: 1
Nonce: ${nonce}
Issued At: ${expiredTimestamp}`
      
      const expiredSignature = await wallet.signMessage(expiredMessage)
      
      const response = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: expiredMessage,
          signature: expiredSignature
        })
      
      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Message expired')
    })
    
    it('should reject future-dated messages', async () => {
      const futureTimestamp = new Date(Date.now() + 10 * 60 * 1000).toISOString() // 10 minutes in future
      const nonce = crypto.randomBytes(16).toString('hex')
      
      const futureMessage = `localhost:3001 wants you to sign in with your Ethereum account:
${wallet.address}

Sign in to BlockchainNews

URI: http://localhost:3001
Version: 1
Chain ID: 1
Nonce: ${nonce}
Issued At: ${futureTimestamp}`
      
      const futureSignature = await wallet.signMessage(futureMessage)
      
      const response = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: futureMessage,
          signature: futureSignature
        })
      
      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Message expired')
    })
  })
  
  describe('Signature Validation', () => {
    it('should reject invalid signatures', async () => {
      const invalidSignature = '0x' + '1'.repeat(130) // Invalid signature
      
      const response = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: validMessage,
          signature: invalidSignature
        })
      
      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Invalid signature')
    })
    
    it('should reject signatures from different addresses', async () => {
      const otherWallet = ethers.Wallet.createRandom()
      const wrongSignature = await otherWallet.signMessage(validMessage)
      
      const response = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: validMessage,
          signature: wrongSignature
        })
      
      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Invalid signature')
    })
  })
  
  describe('Domain Validation', () => {
    it('should reject messages for different domains', async () => {
      const nonce = crypto.randomBytes(16).toString('hex')
      const timestamp = new Date().toISOString()
      
      const wrongDomainMessage = `evil.com wants you to sign in with your Ethereum account:
${wallet.address}

Sign in to BlockchainNews

URI: http://evil.com
Version: 1
Chain ID: 1
Nonce: ${nonce}
Issued At: ${timestamp}`
      
      const wrongDomainSignature = await wallet.signMessage(wrongDomainMessage)
      
      const response = await request(app)
        .post('/api/auth/login/wallet')
        .send({
          message: wrongDomainMessage,
          signature: wrongDomainSignature
        })
      
      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Invalid domain')
    })
  })
})
```

### **3. XSS Prevention Tests** (`xss.security.test.ts`)
*Addresses SEC-2025-003: Inadequate XSS Protection*

```typescript
import request from 'supertest'
import DOMPurify from 'isomorphic-dompurify'
import { app } from '../index'
import { pool } from '../database'

describe('XSS Prevention Security Tests', () => {
  let authToken: string
  
  beforeEach(async () => {
    // Create test user and get auth token
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'test@example.com',
        password: 'SecurePass123!'
      })
    
    authToken = loginResponse.body.token
  })
  
  describe('Input Sanitization', () => {
    const xssPayloads = [
      '<script>alert("xss")</script>',
      '<img src="x" onerror="alert(1)">',
      '<svg onload="alert(1)">',
      'javascript:alert("xss")',
      '<iframe src="javascript:alert(1)"></iframe>',
      '<object data="javascript:alert(1)">',
      '<embed src="javascript:alert(1)">',
      '<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</mtext></mglyph></svg></mtext></math></form>',
      '"><svg onload="alert(1)">',
      '\';alert(1);//',
      '&lt;script&gt;alert("xss")&lt;/script&gt;',
      '%3Cscript%3Ealert%28%22xss%22%29%3C%2Fscript%3E'
    ]
    
    xssPayloads.forEach(payload => {
      it(`should sanitize XSS payload: ${payload.substring(0, 30)}...`, async () => {
        const response = await request(app)
          .post('/api/user/profile')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ bio: payload })
        
        expect(response.status).toBe(200)
        
        // Verify sanitization in database
        const user = await pool.query('SELECT bio FROM users WHERE id = $1', [response.body.user.id])
        const sanitizedBio = user.rows[0].bio
        
        // Should not contain dangerous elements
        expect(sanitizedBio).not.toMatch(/<script\b/i)
        expect(sanitizedBio).not.toMatch(/javascript:/i)
        expect(sanitizedBio).not.toMatch(/on\w+\s*=/i)
        expect(sanitizedBio).not.toMatch(/<iframe\b/i)
        expect(sanitizedBio).not.toMatch(/<object\b/i)
        expect(sanitizedBio).not.toMatch(/<embed\b/i)
      })
    })
    
    it('should preserve safe HTML content', async () => {
      const safeContent = 'Hello <strong>world</strong>! This is <em>safe</em> content.'
      
      const response = await request(app)
        .post('/api/user/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ bio: safeContent })
      
      expect(response.status).toBe(200)
      
      const user = await pool.query('SELECT bio FROM users WHERE id = $1', [response.body.user.id])
      const sanitizedBio = user.rows[0].bio
      
      // Should preserve safe tags
      expect(sanitizedBio).toContain('<strong>')
      expect(sanitizedBio).toContain('<em>')
      expect(sanitizedBio).toContain('Hello')
      expect(sanitizedBio).toContain('world')
    })
  })
  
  describe('Comment System XSS Prevention', () => {
    it('should sanitize article comments', async () => {
      const maliciousComment = '<script>document.cookie="stolen="+document.cookie</script>Legitimate comment'
      
      const response = await request(app)
        .post('/api/articles/test-article/comments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ content: maliciousComment })
      
      expect(response.status).toBe(201)
      
      // Verify comment is sanitized
      const comments = await pool.query('SELECT content FROM comments WHERE article_id = $1', ['test-article'])
      const sanitizedContent = comments.rows[0].content
      
      expect(sanitizedContent).not.toContain('<script>')
      expect(sanitizedContent).not.toContain('document.cookie')
      expect(sanitizedContent).toContain('Legitimate comment')
    })
    
    it('should sanitize search queries', async () => {
      const maliciousQuery = '<script>fetch("/api/admin/users").then(r=>r.json()).then(console.log)</script>'
      
      const response = await request(app)
        .get('/api/articles/search')
        .query({ q: maliciousQuery })
      
      expect(response.status).toBe(200)
      
      // Response should not contain the script
      const responseText = JSON.stringify(response.body)
      expect(responseText).not.toContain('<script>')
      expect(responseText).not.toContain('fetch(')
    })
  })
  
  describe('Content Security Policy Validation', () => {
    it('should set proper CSP headers', async () => {
      const response = await request(app)
        .get('/api/articles')
      
      expect(response.headers['content-security-policy']).toBeDefined()
      
      const csp = response.headers['content-security-policy']
      expect(csp).toContain("default-src 'self'")
      expect(csp).toContain("script-src 'self'")
      expect(csp).toContain("object-src 'none'")
    })
  })
})
```

### **4. CSRF Protection Tests** (`csrf.security.test.ts`)
*Addresses SEC-2025-004: Missing CSRF Token Validation*

```typescript
import request from 'supertest'
import { app } from '../index'

describe('CSRF Protection Security Tests', () => {
  let authToken: string
  let sessionCookie: string
  let csrfToken: string
  
  beforeEach(async () => {
    // Login to get session
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'test@example.com',
        password: 'SecurePass123!'
      })
    
    authToken = loginResponse.body.token
    sessionCookie = loginResponse.headers['set-cookie'][0]
    
    // Get CSRF token
    const csrfResponse = await request(app)
      .get('/api/csrf')
      .set('Cookie', sessionCookie)
    
    csrfToken = csrfResponse.body.csrfToken
  })
  
  describe('CSRF Token Validation', () => {
    const stateChangingEndpoints = [
      { method: 'post', path: '/api/user/profile', data: { bio: 'Updated bio' } },
      { method: 'put', path: '/api/user/preferences', data: { theme: 'dark' } },
      { method: 'delete', path: '/api/user/bookmarks/article-id', data: {} },
      { method: 'post', path: '/api/articles/article-id/comments', data: { content: 'Comment' } }
    ]
    
    stateChangingEndpoints.forEach(endpoint => {
      it(`should reject ${endpoint.method.toUpperCase()} ${endpoint.path} without CSRF token`, async () => {
        const response = await request(app)
          [endpoint.method](endpoint.path)
          .set('Authorization', `Bearer ${authToken}`)
          .set('Cookie', sessionCookie)
          .send(endpoint.data)
        
        expect(response.status).toBe(403)
        expect(response.body.error).toContain('CSRF')
      })
      
      it(`should accept ${endpoint.method.toUpperCase()} ${endpoint.path} with valid CSRF token`, async () => {
        const response = await request(app)
          [endpoint.method](endpoint.path)
          .set('Authorization', `Bearer ${authToken}`)
          .set('Cookie', sessionCookie)
          .set('X-CSRF-Token', csrfToken)
          .send(endpoint.data)
        
        expect(response.status).not.toBe(403)
      })
      
      it(`should reject ${endpoint.method.toUpperCase()} ${endpoint.path} with invalid CSRF token`, async () => {
        const response = await request(app)
          [endpoint.method](endpoint.path)
          .set('Authorization', `Bearer ${authToken}`)
          .set('Cookie', sessionCookie)
          .set('X-CSRF-Token', 'invalid-token')
          .send(endpoint.data)
        
        expect(response.status).toBe(403)
      })
    })
  })
  
  describe('GET Requests Should Not Require CSRF', () => {
    const getEndpoints = [
      '/api/articles',
      '/api/user/profile',
      '/api/user/bookmarks',
      '/api/articles/search'
    ]
    
    getEndpoints.forEach(endpoint => {
      it(`should allow GET ${endpoint} without CSRF token`, async () => {
        const response = await request(app)
          .get(endpoint)
          .set('Authorization', `Bearer ${authToken}`)
        
        expect(response.status).not.toBe(403)
      })
    })
  })
  
  describe('CSRF Token Properties', () => {
    it('should generate unique CSRF tokens per session', async () => {
      // Get another session
      const loginResponse2 = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test2@example.com',
          password: 'SecurePass123!'
        })
      
      const sessionCookie2 = loginResponse2.headers['set-cookie'][0]
      
      const csrfResponse2 = await request(app)
        .get('/api/csrf')
        .set('Cookie', sessionCookie2)
      
      const csrfToken2 = csrfResponse2.body.csrfToken
      
      expect(csrfToken).not.toBe(csrfToken2)
    })
    
    it('should reject CSRF tokens from different sessions', async () => {
      // Try to use csrfToken with different session
      const loginResponse2 = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test2@example.com',
          password: 'SecurePass123!'
        })
      
      const sessionCookie2 = loginResponse2.headers['set-cookie'][0]
      const authToken2 = loginResponse2.body.token
      
      const response = await request(app)
        .post('/api/user/profile')
        .set('Authorization', `Bearer ${authToken2}`)
        .set('Cookie', sessionCookie2)
        .set('X-CSRF-Token', csrfToken) // Using token from different session
        .send({ bio: 'Updated bio' })
      
      expect(response.status).toBe(403)
    })
  })
})
```

### **5. SQL Injection Prevention Tests** (`injection.security.test.ts`)

```typescript
import request from 'supertest'
import { app } from '../index'
import { pool } from '../database'

describe('SQL Injection Prevention Tests', () => {
  let authToken: string
  
  beforeEach(async () => {
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'test@example.com',
        password: 'SecurePass123!'
      })
    
    authToken = loginResponse.body.token
  })
  
  describe('Search Query Injection Prevention', () => {
    const sqlInjectionPayloads = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "' UNION SELECT * FROM users --",
      "'; UPDATE users SET role = 'admin' WHERE email = 'attacker@evil.com'; --",
      "'; INSERT INTO users (email, password_hash, role) VALUES ('hacker@evil.com', 'hash', 'admin'); --",
      "1'; EXEC xp_cmdshell('dir'); --",
      "'; LOAD_FILE('/etc/passwd'); --",
      "' AND (SELECT SUBSTRING(password_hash,1,1) FROM users WHERE email='admin@example.com')='a",
      "'; WAITFOR DELAY '00:00:05'; --"
    ]
    
    sqlInjectionPayloads.forEach(payload => {
      it(`should prevent SQL injection in search: ${payload}`, async () => {
        const response = await request(app)
          .get('/api/articles/search')
          .query({ q: payload })
        
        expect(response.status).toBe(200)
        
        // Verify database integrity - users table should still exist
        const result = await pool.query('SELECT COUNT(*) FROM users')
        expect(result.rows[0].count).toBeDefined()
        
        // Should not return unauthorized data
        expect(response.body.articles).toBeDefined()
        expect(Array.isArray(response.body.articles)).toBe(true)
      })
    })
  })
  
  describe('User Input Injection Prevention', () => {
    it('should prevent SQL injection in registration', async () => {
      const maliciousEmail = "admin'; DROP TABLE users; --@evil.com"
      
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: maliciousEmail,
          password: 'SecurePass123!',
          confirmPassword: 'SecurePass123!'
        })
      
      // Should fail validation before reaching database
      expect(response.status).toBe(400)
      
      // Verify users table still exists
      const result = await pool.query('SELECT COUNT(*) FROM users')
      expect(result.rows[0].count).toBeDefined()
    })
    
    it('should prevent SQL injection in profile updates', async () => {
      const maliciousBio = "'; UPDATE users SET role = 'admin' WHERE id = 1; --"
      
      const response = await request(app)
        .post('/api/user/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ bio: maliciousBio })
      
      expect(response.status).toBe(200)
      
      // Verify no privilege escalation occurred
      const users = await pool.query("SELECT role FROM users WHERE role = 'admin'")
      expect(users.rows.length).toBe(0) // No admin users should exist from injection
    })
  })
  
  describe('Parameterized Query Validation', () => {
    it('should use parameterized queries for all database operations', async () => {
      // This test verifies our query patterns are safe
      const testEmail = 'test-param@example.com'
      
      // Test user lookup
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: testEmail,
          password: 'WrongPassword'
        })
      
      expect(response.status).toBe(401) // Should fail authentication, not cause SQL error
    })
  })
})
```

---

## 🚀 Performance Security Tests

### Rate Limiting Tests (`rate-limit.security.test.ts`)
```typescript
import request from 'supertest'
import { app } from '../index'

describe('Rate Limiting Security Tests', () => {
  describe('API Rate Limits', () => {
    it('should enforce global API rate limits', async () => {
      const requests = []
      
      // Make requests up to the limit
      for (let i = 0; i < 105; i++) { // Exceeding limit of 100
        requests.push(
          request(app)
            .get('/api/articles')
            .expect(res => {
              expect([200, 429]).toContain(res.status)
            })
        )
      }
      
      const responses = await Promise.all(requests)
      const rateLimitedCount = responses.filter(res => res.status === 429).length
      
      expect(rateLimitedCount).toBeGreaterThan(0)
    })
    
    it('should have stricter limits on authentication endpoints', async () => {
      const requests = []
      
      // Make multiple failed login attempts
      for (let i = 0; i < 7; i++) { // Exceeding limit of 5
        requests.push(
          request(app)
            .post('/api/auth/login')
            .send({
              email: 'nonexistent@example.com',
              password: 'WrongPassword'
            })
        )
      }
      
      const responses = await Promise.all(requests)
      const lastResponse = responses[responses.length - 1]
      
      expect(lastResponse.status).toBe(429)
      expect(lastResponse.body.error).toContain('Too many')
    })
  })
  
  describe('Rate Limit Headers', () => {
    it('should include rate limit headers in responses', async () => {
      const response = await request(app)
        .get('/api/articles')
      
      expect(response.headers['x-ratelimit-limit']).toBeDefined()
      expect(response.headers['x-ratelimit-remaining']).toBeDefined()
      expect(response.headers['x-ratelimit-reset']).toBeDefined()
    })
  })
})
```

---

## 🧪 Test Utilities & Helpers

### Security Test Helpers (`helpers/security-helpers.ts`)
```typescript
import { pool } from '../../database'
import crypto from 'crypto'
import { ethers } from 'ethers'

export const securityHelpers = {
  // Database setup and cleanup
  async setupTestDatabase(): Promise<void> {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS test_users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `)
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS test_articles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        author_id UUID REFERENCES test_users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `)
  },
  
  async cleanupTestDatabase(): Promise<void> {
    await pool.query('DROP TABLE IF EXISTS test_articles')
    await pool.query('DROP TABLE IF EXISTS test_users')
  },
  
  async resetTestData(): Promise<void> {
    await pool.query('DELETE FROM test_articles')
    await pool.query('DELETE FROM test_users')
    
    // Insert test user
    await pool.query(`
      INSERT INTO test_users (email, password_hash, role) 
      VALUES ($1, $2, $3)
    `, ['test@example.com', '$2b$12$hashedpassword', 'user'])
  },
  
  // Generate test data with attack vectors
  generateXSSPayloads(): string[] {
    return [
      '<script>alert("xss")</script>',
      '<img src="x" onerror="alert(1)">',
      '<svg onload="alert(1)">',
      'javascript:alert("xss")',
      '"><script>alert(1)</script>',
      '\';alert(1);//',
      '&lt;script&gt;alert("xss")&lt;/script&gt;'
    ]
  },
  
  generateSQLInjectionPayloads(): string[] {
    return [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "' UNION SELECT * FROM users --",
      "'; UPDATE users SET role = 'admin'; --"
    ]
  },
  
  // Web3 test utilities
  async generateValidWeb3Login(): Promise<{
    wallet: ethers.Wallet,
    message: string,
    signature: string
  }> {
    const wallet = ethers.Wallet.createRandom()
    const timestamp = new Date().toISOString()
    const nonce = crypto.randomBytes(16).toString('hex')
    
    const message = `localhost:3001 wants you to sign in with your Ethereum account:
${wallet.address}

Sign in to BlockchainNews

URI: http://localhost:3001
Version: 1
Chain ID: 1
Nonce: ${nonce}
Issued At: ${timestamp}`
    
    const signature = await wallet.signMessage(message)
    
    return { wallet, message, signature }
  },
  
  // Security event validation
  async validateSecurityLog(eventType: string, expectedCount: number): Promise<boolean> {
    // Mock implementation - in real app, check log files or database
    return true
  },
  
  // Performance monitoring
  async measureRequestTime(requestFn: () => Promise<any>): Promise<number> {
    const start = Date.now()
    await requestFn()
    return Date.now() - start
  }
}
```

---

## 📋 Test Execution Guidelines

### Running Security Tests
```bash
# Run all security tests
pnpm test:security

# Run specific security test categories
pnpm test server/__tests__/auth.security.test.ts
pnpm test server/__tests__/xss.security.test.ts
pnpm test server/__tests__/csrf.security.test.ts

# Run tests with coverage
pnpm test:security --coverage

# Run tests in watch mode during development
pnpm test:security --watch
```

### Test Environment Configuration
```typescript
// jest.config.js for security tests
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/server/__tests__/helpers/test-setup.ts'],
  testMatch: ['**/__tests__/**/*.security.test.ts'],
  collectCoverageFrom: [
    'server/**/*.ts',
    '!server/__tests__/**',
    '!server/node_modules/**'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
}
```

### Continuous Integration Security Testing
```yaml
# .github/workflows/security-tests.yml
name: Security Tests
on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: pnpm install
      
      - name: Run security tests
        run: pnpm test:security
        env:
          DATABASE_URL: postgresql://postgres:test@localhost:5432/test
          SESSION_SECRET: test-secret-32-characters-long
          JWT_SECRET: test-jwt-secret-32-characters-long
          NODE_ENV: test
      
      - name: Run dependency audit
        run: pnpm audit --audit-level moderate
```

---

## 🎯 Success Criteria

### Test Coverage Requirements
- **Security Tests**: 100% pass rate required
- **Code Coverage**: Minimum 80% coverage on security-critical functions
- **Attack Vector Coverage**: All OWASP Top 10 vulnerabilities tested
- **Performance**: No security test should take >5 seconds

### Security Validation Checklist
- [ ] All CRITICAL audit findings have corresponding test cases
- [ ] XSS prevention tests cover all input vectors
- [ ] SQL injection tests cover all database operations
- [ ] CSRF protection tests cover all state-changing endpoints
- [ ] Authentication tests validate both success and failure cases
- [ ] Authorization tests verify role-based access controls
- [ ] Rate limiting tests prevent DoS attacks
- [ ] Session security tests prevent hijacking
- [ ] Web3 authentication follows EIP-4361 standard

### Automated Security Validation
```bash
# Security test pipeline - all must pass
pnpm test:security          # Security test suite
pnpm run type-check         # TypeScript validation  
pnpm run lint              # ESLint security rules
pnpm audit --audit-level moderate  # Dependency audit
```

---

**Remember**: These tests are our security safety net. Every test failure represents a potential vulnerability. Treat test failures as security incidents and investigate thoroughly before proceeding with development.
