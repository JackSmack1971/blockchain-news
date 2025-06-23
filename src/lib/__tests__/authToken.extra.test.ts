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

  it('wraps errors in TokenError for apiRequest', async () => {
    (fetch as unknown as vi.Mock).mockRejectedValueOnce(new Error('boom'));
    const { apiRequest } = await loadModule();
    await expect(apiRequest('/fail')).rejects.toHaveProperty('name', 'TokenError');
  });
});
