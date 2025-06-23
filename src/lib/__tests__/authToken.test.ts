import { describe, it, expect, beforeEach, vi } from 'vitest';
import { setToken, getToken, clearToken } from '../authToken';

const createToken = (exp: number): string => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .toString('base64')
    .replace(/=/g, '');
  const payload = Buffer.from(JSON.stringify({ exp }))
    .toString('base64')
    .replace(/=/g, '');
  return `${header}.${payload}.sig`;
};

describe('authToken', () => {
  beforeEach(() => {
    clearToken();
  });

  it('stores and retrieves token', () => {
    const token = createToken(Math.floor(Date.now() / 1000) + 60);
    setToken(token);
    expect(getToken()).toBe(token);
  });

  it('clears token', () => {
    const token = createToken(Math.floor(Date.now() / 1000) + 60);
    setToken(token);
    clearToken();
    expect(getToken()).toBeNull();
  });
});
