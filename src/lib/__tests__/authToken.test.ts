import { describe, it, expect, beforeEach } from 'vitest';
import Cookies from 'js-cookie';
import { setToken, getToken, clearToken } from '../authToken';

describe('authToken', () => {
  beforeEach(() => {
    clearToken();
  });

  it('stores and retrieves token', () => {
    setToken({ user: { id: '1' } });
    const token = getToken<{ id: string }>();
    expect(token?.user.id).toBe('1');
  });

  it('clears token', () => {
    setToken({ user: { id: '1' } });
    clearToken();
    const token = Cookies.get('auth_token');
    expect(token).toBeUndefined();
  });
});
