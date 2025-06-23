import { describe, it, expect } from 'vitest'
import { sanitizeInput } from '../security'

// vitest runs in jsdom environment enabling DOMPurify

describe('sanitizeInput', () => {
  it('removes script tags and attributes', () => {
    const dirty = '<img src=x onerror=alert(1)><script>alert(2)</script>'
    const clean = sanitizeInput(dirty)
    expect(clean).not.toMatch(/<script/)
    expect(clean).not.toMatch(/onerror/)
  })

  it('trims whitespace and keeps text', () => {
    const dirty = '  hello <b>world</b> '
    const clean = sanitizeInput(dirty)
    expect(clean).toBe('hello world')
  })
})
