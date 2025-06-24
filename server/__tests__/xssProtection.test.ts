import { describe, it, beforeEach, afterAll, expect } from 'vitest'
import request from 'supertest'

process.env.SESSION_SECRET = 'a-very-long-and-secure-session-secret-key'
process.env.RATE_LIMIT_MAX = '10'
process.env.RATE_LIMIT_WINDOW = '1000'
process.env.DATABASE_URL = 'postgresql://appuser:testpass@localhost/appdb'
process.env.NODE_ENV = 'development'

const {
  app,
  resetUsers,
  resetComments,
  getComments,
  resetNonces,
  _authLimiter,
  shutdown,
} = await import('../index.ts')

const xssPayloads = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg/onload=alert(1)>',
  'javascript:alert(1)',
  "'\"><script>alert(1)</script>",
  '&lt;script&gt;alert("xss")&lt;/script&gt;'
]

describe('XSS protection endpoints', () => {
  let agent: request.SuperAgentTest

  beforeEach(async () => {
    await resetUsers()
    resetComments()
    resetNonces()
    _authLimiter.resetKey('::ffff:127.0.0.1')
    _authLimiter.resetKey('127.0.0.1')
    agent = request.agent(app)
    await agent
      .post('/api/register')
      .send({ username: 'alice', email: 'a@a.com', password: 'Secret1!', confirmPassword: 'Secret1!' })
      .expect(200)
  })

  afterAll(async () => {
    await shutdown()
  })

  describe('profile updates', () => {
    xssPayloads.forEach(payload => {
      it(`sanitizes bio payload: ${payload}`, async () => {
        await agent.post('/api/profile').send({ bio: payload }).expect(200)
        const res = await agent.get('/api/token').expect(200)
        const bio = res.body.user.bio
        expect(bio).not.toMatch(/<script/i)
        expect(bio).not.toMatch(/javascript:/i)
      })
    })
  })

  describe('article comments', () => {
    xssPayloads.forEach(payload => {
      it(`sanitizes comment payload: ${payload}`, async () => {
        await agent.post('/api/articles/test/comments').send({ content: payload }).expect(201)
        const comment = getComments()[0]
        expect(comment.content).not.toMatch(/<script/i)
        expect(comment.content).not.toMatch(/javascript:/i)
        resetComments()
      })
    })
  })

  describe('search query', () => {
    xssPayloads.forEach(payload => {
      it(`sanitizes search payload: ${payload}`, async () => {
        const res = await agent.get('/api/articles/search').query({ q: payload }).expect(200)
        expect(res.body.query).not.toMatch(/<script/i)
        expect(res.body.query).not.toMatch(/javascript:/i)
      })
    })
  })
})
