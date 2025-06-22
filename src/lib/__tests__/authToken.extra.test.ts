import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.stubGlobal('fetch', vi.fn());

// Need dynamic import to apply env vars before module initialization

const loadModule = async () => {
  vi.resetModules();
  return await import('../authToken');
};

describe('authToken failure scenarios', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('returns null when getToken fails', async () => {
    (fetch as unknown as vi.Mock).mockRejectedValueOnce(new Error('net'));
    const { getToken } = await loadModule();
    const token = await getToken();
    expect(token).toBeNull();
  });

  it('wraps errors in TokenError for apiRequest', async () => {
    (fetch as unknown as vi.Mock).mockRejectedValueOnce(new Error('boom'));
    const { apiRequest } = await loadModule();
    await expect(apiRequest('/fail')).rejects.toHaveProperty('name', 'TokenError');
  });

  it('passes cookie options from env', async () => {
    process.env.COOKIE_DOMAIN = 'example.com';
    process.env.COOKIE_MAX_AGE = '1000';
    process.env.NODE_ENV = 'production';
    vi.resetModules();
    const { setToken } = await import('../authToken');
    (fetch as unknown as vi.Mock).mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(null) });
    await setToken({ user: { id: '99' } });
    const body = JSON.parse((fetch as vi.Mock).mock.calls[0][1].body as string);
    expect(body.cookie.domain).toBe('example.com');
    expect(body.cookie.maxAge).toBe(1000);
    expect(body.cookie.secure).toBe(true);
    expect(body.cookie.httpOnly).toBe(true);
  });
});
