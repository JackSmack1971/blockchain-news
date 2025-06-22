import { describe, it, expect, beforeEach, vi } from 'vitest';
import { setToken, getToken, clearToken } from '../authToken';

vi.stubGlobal('fetch', vi.fn());

describe('authToken', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('stores and retrieves token', async () => {
    (fetch as unknown as vi.Mock).mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(null) });
    (fetch as unknown as vi.Mock).mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ user: { id: '1' } }) });
    await setToken({ user: { id: '1' } });
    const token = await getToken<{ id: string }>();
    expect((fetch as vi.Mock).mock.calls[0][0]).toBe('/api/token');
    expect(token?.user.id).toBe('1');
  });

  it('clears token', async () => {
    (fetch as unknown as vi.Mock).mockResolvedValue({ ok: true, json: () => Promise.resolve(null) });
    await clearToken();
    expect((fetch as vi.Mock).mock.calls[0][0]).toBe('/api/token');
  });
});
