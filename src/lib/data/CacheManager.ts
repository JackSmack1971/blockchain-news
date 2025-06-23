import Redis from 'ioredis';
import { logError } from '../errors';

export class CacheError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CacheError';
  }
}

interface CacheOptions {
  ttl?: number;
  maxEntries?: number;
  maxMemoryBytes?: number;
}

interface CacheEntry<T> {
  value: T;
  expires: number;
  size: number;
}

export default class CacheManager {
  private memory = new Map<string, CacheEntry<unknown>>();
  private redis?: Redis;
  private ttl: number;
  private maxEntries: number;
  private maxBytes: number;
  private currentBytes = 0;

  constructor(options: CacheOptions = {}) {
    this.ttl = options.ttl ?? 300;
    this.maxEntries = options.maxEntries ?? 100;
    this.maxBytes = options.maxMemoryBytes ?? 50 * 1024 * 1024;
    const url = process.env.REDIS_URL;
    if (url) {
      this.redis = new Redis(url);
    }
  }

  private setMemory(key: string, value: unknown): void {
    const data = JSON.stringify(value);
    const size = Buffer.byteLength(data);
    const entry = { value, expires: Date.now() + this.ttl * 1000, size };
    const existing = this.memory.get(key);
    if (existing) this.currentBytes -= existing.size;
    this.memory.set(key, entry);
    this.currentBytes += size;
    this.enforceLimits();
  }

  private enforceLimits(): void {
    while (
      (this.memory.size > this.maxEntries || this.currentBytes > this.maxBytes) &&
      this.memory.size
    ) {
      const firstKey = this.memory.keys().next().value as string;
      const entry = this.memory.get(firstKey);
      if (entry) this.currentBytes -= entry.size;
      this.memory.delete(firstKey);
    }
  }

  async get<T>(key: string): Promise<T | null> {
    const entry = this.memory.get(key);
    if (entry && entry.expires > Date.now()) {
      return entry.value as T;
    }
    if (entry) {
      this.currentBytes -= entry.size;
      this.memory.delete(key);
    }
    if (!this.redis) return null;
    try {
      const data = await this.redis.get(key);
      if (!data) return null;
      const parsed = JSON.parse(data) as T;
      this.setMemory(key, parsed);
      return parsed;
    } catch (err) {
      logError(err, 'CacheManager:get');
      throw new CacheError('Redis get failed');
    }
  }

  async set<T>(key: string, value: T): Promise<void> {
    this.setMemory(key, value);
    if (!this.redis) return;
    try {
      await this.redis.set(key, JSON.stringify(value), 'EX', this.ttl);
    } catch (err) {
      logError(err, 'CacheManager:set');
      throw new CacheError('Redis set failed');
    }
  }

  async clear(key: string): Promise<void> {
    const entry = this.memory.get(key);
    if (entry) {
      this.currentBytes -= entry.size;
      this.memory.delete(key);
    }
    if (!this.redis) return;
    try {
      await this.redis.del(key);
    } catch (err) {
      logError(err, 'CacheManager:clear');
      throw new CacheError('Redis clear failed');
    }
  }
}
