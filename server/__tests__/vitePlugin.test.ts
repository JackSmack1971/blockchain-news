import { describe, it, expect, vi } from 'vitest'
import { securityPlugin } from '../../vite.config'

describe('securityPlugin', () => {
  it('adds CSP nonce via middleware', () => {
    let captured: any
    const server = {
      middlewares: {
        use(fn: any) {
          captured = fn
        },
      },
    } as any

    securityPlugin().configureServer!(server)

    const res: any = { setHeader: vi.fn(), locals: {} }
    const next = vi.fn()
    captured({}, res, next)

    const call = res.setHeader.mock.calls.find((c: any[]) => c[0] === 'Content-Security-Policy')
    expect(call?.[1]).toMatch(/nonce-[^';]+/)
    expect(next).toHaveBeenCalled()
  })
})
