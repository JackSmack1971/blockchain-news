import { describe, it, expect, beforeEach, vi } from 'vitest';
import SecureTokenManager from '../auth/SecureTokenManager';

const createToken = (exp: number): string => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .toString('base64')
    .replace(/=/g, '');
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64')
    .replace(/=/g, '');
  return `${header}.${payload}.signature`;
};

describe('SecureTokenManager', () => {
  beforeEach(() => {
    const manager = SecureTokenManager.getInstance();
    manager.clearTokens();
    vi.useRealTimers();
  });

  it('returns stored token if valid', () => {
    const token = createToken(Math.floor(Date.now() / 1000) + 60);
    const manager = SecureTokenManager.getInstance();
    manager.setTokens(token);
    expect(manager.getToken()).toBe(token);
  });

  it('returns null for expired token', () => {
    const token = createToken(Math.floor(Date.now() / 1000) - 60);
    const manager = SecureTokenManager.getInstance();
    manager.setTokens(token);
    expect(manager.getToken()).toBeNull();
  });

  it('clears token after cleanup interval', () => {
    vi.useFakeTimers();
    const token = createToken(Math.floor(Date.now() / 1000) + 60);
    const manager = SecureTokenManager.getInstance();
    manager.setTokens(token);
    vi.advanceTimersByTime(24 * 60 * 60 * 1000 + 1);
    expect(manager.getToken()).toBeNull();
    vi.useRealTimers();
  });
});
