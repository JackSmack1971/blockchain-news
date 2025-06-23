import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

let CacheManager: any;
let CacheError: any;
let mockRedis: any;

class MockRedis {
  store = new Map<string, string>();
  get = vi.fn(async (key: string) => this.store.get(key) ?? null);
  set = vi.fn(async (key: string, value: string, mode: string, ttl: number) => {
    this.store.set(key, value);
  });
  del = vi.fn(async (key: string) => {
    this.store.delete(key);
  });
}

beforeEach(async () => {
  mockRedis = new MockRedis();
  vi.doMock('ioredis', () => ({ default: vi.fn(() => mockRedis) }));
  process.env.REDIS_URL = 'redis://localhost:6379';
  const mod = await import('../CacheManager');
  CacheManager = mod.default;
  CacheError = mod.CacheError;
  vi.useFakeTimers();
});

afterEach(() => {
  vi.resetModules();
  vi.useRealTimers();
});

describe('CacheManager', () => {
  it('returns value from memory cache', async () => {
    const cache = new CacheManager({ ttl: 1 });
    await cache.set('a', { v: 1 });
    const val = await cache.get('a');
    expect(val).toEqual({ v: 1 });
    expect(mockRedis.set).toHaveBeenCalled();
    expect(mockRedis.get).not.toHaveBeenCalled();
  });

  it('falls back to redis on memory miss', async () => {
    const cache1 = new CacheManager({ ttl: 1 });
    await cache1.set('b', { v: 2 });
    const cache2 = new CacheManager({ ttl: 1 });
    const val = await cache2.get('b');
    expect(val).toEqual({ v: 2 });
    expect(mockRedis.get).toHaveBeenCalled();
  });

  it('throws CacheError on redis failure', async () => {
    mockRedis.get.mockRejectedValueOnce(new Error('fail'));
    const cache = new CacheManager();
    await expect(cache.get('missing')).rejects.toBeInstanceOf(CacheError);
  });
});
