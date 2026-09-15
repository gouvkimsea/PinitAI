import crypto from 'crypto';
import IORedis from 'ioredis';
import { config } from '../config';
import { logger } from '../utils/logger';

/**
 * Token Revocation & Invalidation Service
 * Provides token denylisting with TTL auto-cleanup so compromised or logged-out JWTs
 * are immediately rejected even prior to expiration.
 */
class TokenRevocationService {
  private inMemoryDenylist = new Map<string, number>(); // tokenHash -> expiryTimestamp
  private redisClient: IORedis | null = null;
  private readonly defaultTtlMs = 7 * 24 * 60 * 60 * 1000; // 7 days

  constructor() {
    if (config.redisUrl && config.redisUrl.trim().length > 0) {
      try {
        this.redisClient = new IORedis(config.redisUrl, {
          lazyConnect: true,
          enableOfflineQueue: false,
          maxRetriesPerRequest: 1,
        });
        this.redisClient.connect().catch((err) => {
          logger.warn('TokenRevocationService Redis connection failed, using in-memory denylist', { error: err.message });
          this.redisClient = null;
        });
      } catch {
        this.redisClient = null;
      }
    }

    // Periodically purge expired tokens from in-memory map
    setInterval(() => this.purgeExpiredInMemory(), 60000).unref();
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  private purgeExpiredInMemory(): void {
    const now = Date.now();
    for (const [hash, exp] of this.inMemoryDenylist.entries()) {
      if (exp <= now) {
        this.inMemoryDenylist.delete(hash);
      }
    }
  }

  /**
   * Revokes a token by adding its hash to the denylist.
   */
  async revokeToken(token: string, expiresInMs = this.defaultTtlMs): Promise<void> {
    const tokenHash = this.hashToken(token);
    const expiry = Date.now() + expiresInMs;

    this.inMemoryDenylist.set(tokenHash, expiry);

    if (this.redisClient && this.redisClient.status === 'ready') {
      try {
        const ttlSec = Math.max(1, Math.ceil(expiresInMs / 1000));
        await this.redisClient.set(`revoked_jwt:${tokenHash}`, '1', 'EX', ttlSec);
      } catch (err) {
        logger.warn('Failed to persist revoked token to Redis', { error: (err as Error).message });
      }
    }
  }

  /**
   * Checks if a token is in the revocation denylist.
   */
  async isRevoked(token: string): Promise<boolean> {
    const tokenHash = this.hashToken(token);

    const memoryExp = this.inMemoryDenylist.get(tokenHash);
    if (memoryExp) {
      if (memoryExp > Date.now()) return true;
      this.inMemoryDenylist.delete(tokenHash);
    }

    if (this.redisClient && this.redisClient.status === 'ready') {
      try {
        const exists = await this.redisClient.exists(`revoked_jwt:${tokenHash}`);
        return exists === 1;
      } catch {
        return false;
      }
    }

    return false;
  }
}

export const tokenRevocationService = new TokenRevocationService();
