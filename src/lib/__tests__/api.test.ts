import { describe, it, expect, beforeEach, vi } from 'vitest';
import { apiFetch } from '../api';
import { NetworkError } from '../errors';

vi.stubGlobal('fetch', vi.fn());

describe('apiFetch', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('returns json on success', async () => {
    (fetch as unknown as vi.Mock).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ ok: 1 }),
    });
    const data = await apiFetch<{ ok: number }>('/good');
    expect(data.ok).toBe(1);
  });

  it('retries on failure', async () => {
    (fetch as unknown as vi.Mock)
      .mockRejectedValueOnce(new Error('fail'))
      .mockResolvedValue({ ok: true, json: () => Promise.resolve({ retry: true }) });
    const data = await apiFetch<{ retry: boolean }>('/retry', {}, { retries: 1, timeout: 100 });
    expect((fetch as vi.Mock).mock.calls.length).toBe(2);
    expect(data.retry).toBe(true);
  });

  it('throws after retries', async () => {
    (fetch as unknown as vi.Mock).mockRejectedValue(new Error('fail'));
    await expect(apiFetch('/err', {}, { retries: 1, timeout: 10 })).rejects.toBeInstanceOf(NetworkError);
  });
});
