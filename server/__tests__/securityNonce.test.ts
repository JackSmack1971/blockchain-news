import { describe, it, beforeEach } from 'vitest'
import request from 'supertest'
import { expectDefaultSecurityHeaders } from './utils/expectSecurityHeaders'

process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key'
process.env.RATE_LIMIT_MAX = '10'
process.env.RATE_LIMIT_WINDOW = '1000'
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb'
process.env.SIGNIN_DOMAIN = "localhost:3001"
process.env.SIGNIN_CHAIN_ID = "1"

const { app, resetUsers, resetNonces, _authLimiter, shutdown } = await import('../index.ts')

describe('security nonce', () => {
  beforeEach(async () => {
    await resetUsers()
    resetNonces()
    _authLimiter.resetKey('::ffff:127.0.0.1')
    _authLimiter.resetKey('127.0.0.1')
  })

  afterAll(async () => {
    await shutdown()
  })

  it('generates a unique nonce per request', async () => {
    const res1 = await request(app).get('/')
    expectDefaultSecurityHeaders(res1)
    const nonce1 = /nonce-([^']+)/.exec(res1.headers['content-security-policy'] || '')?.[1]

    const res2 = await request(app).get('/')
    expectDefaultSecurityHeaders(res2)
    const nonce2 = /nonce-([^']+)/.exec(res2.headers['content-security-policy'] || '')?.[1]

    expect(nonce1).toBeDefined()
    expect(nonce2).toBeDefined()
    expect(nonce1).not.toBe(nonce2)
  })
})
