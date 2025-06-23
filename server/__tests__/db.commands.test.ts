import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest'

let backupDatabase: typeof import('../db').backupDatabase
let restoreDatabase: typeof import('../db').restoreDatabase
let DatabaseError: typeof import('../db').DatabaseError
let execFileMock: ReturnType<typeof vi.fn>

beforeEach(async () => {
  execFileMock = vi.fn((cmd: string, args: string[], cb: (err: Error | null) => void) => {
    cb(new Error('fail'))
  })
  vi.doMock('node:child_process', () => ({ execFile: execFileMock }))
  const mod = await import('../db')
  backupDatabase = mod.backupDatabase
  restoreDatabase = mod.restoreDatabase
  DatabaseError = mod.DatabaseError
})

afterEach(() => {
  vi.resetModules()
})

describe('database command execution errors', () => {
  it('backupDatabase rejects on command error', async () => {
    await expect(backupDatabase('/tmp/test.dump')).rejects.toBeInstanceOf(DatabaseError)
    expect(execFileMock).toHaveBeenCalled()
  })

  it('restoreDatabase rejects on command error', async () => {
    await expect(restoreDatabase('/tmp/test.dump')).rejects.toBeInstanceOf(DatabaseError)
    expect(execFileMock).toHaveBeenCalled()
  })

  it('rejects non absolute path', async () => {
    await expect(backupDatabase('relative/path')).rejects.toBeInstanceOf(DatabaseError)
    await expect(restoreDatabase('relative/path')).rejects.toBeInstanceOf(DatabaseError)
  })

  it('rejects path traversal', async () => {
    await expect(backupDatabase('/tmp/../etc/passwd')).rejects.toBeInstanceOf(DatabaseError)
  })
})
