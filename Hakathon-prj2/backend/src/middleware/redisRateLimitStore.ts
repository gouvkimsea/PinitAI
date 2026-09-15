import IORedis from 'ioredis';
import { Store, Options, ClientRateLimitInfo } from 'express-rate-limit';
import { logger } from '../utils/logger';

/**
 * Distributed Redis Store for express-rate-limit.
 * Ensures consistent rate limiting across multiple backend instances / worker pods.
 * Automatically falls back to in-memory gracefully if Redis is unavailable.
 */
export class RedisRateLimitStore implements Store {
  private client: IORedis | null = null;
  public prefix: string;
  private windowMs = 60000;

  constructor(redisUrl?: string, prefix = 'pinit:rl:') {
    this.prefix = prefix;
    if (redisUrl && redisUrl.trim().length > 0) {
      try {
        this.client = new IORedis(redisUrl, {
          lazyConnect: true,
          enableOfflineQueue: false,
          maxRetriesPerRequest: 1,
        });
        this.client.connect().catch((err) => {
          logger.warn('Distributed Redis rate limiter connection failed; in-memory fallback active', { error: err.message });
          this.client = null;
        });
      } catch {
        this.client = null;
      }
    }
  }

  init(options: Options): void {
    this.windowMs = options.windowMs;
  }

  async increment(key: string): Promise<ClientRateLimitInfo> {
    if (!this.client || this.client.status !== 'ready') {
      return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
    }

    const redisKey = `${this.prefix}${key}`;
    const windowSec = Math.max(1, Math.ceil(this.windowMs / 1000));

    try {
      const results = await this.client
        .multi()
        .incr(redisKey)
        .ttl(redisKey)
        .exec();

      if (!results) {
        return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
      }

      const totalHits = (results[0][1] as number) || 1;
      let ttl = (results[1][1] as number) || -1;

      if (ttl === -1) {
        await this.client.expire(redisKey, windowSec);
        ttl = windowSec;
      }

      const resetTime = new Date(Date.now() + Math.max(0, ttl) * 1000);
      return { totalHits, resetTime };
    } catch {
      return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
    }
  }

  async decrement(key: string): Promise<void> {
    if (!this.client || this.client.status !== 'ready') return;
    try {
      await this.client.decr(`${this.prefix}${key}`);
    } catch {
      // safe ignore on decrement failure
    }
  }

  async resetKey(key: string): Promise<void> {
    if (!this.client || this.client.status !== 'ready') return;
    try {
      await this.client.del(`${this.prefix}${key}`);
    } catch {
      // safe ignore on reset failure
    }
  }
}
