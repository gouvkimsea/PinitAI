/**
 * Generic Bounded In-Memory LRU Cache with TTL Expiration
 *
 * Provides O(1) reads, writes, and evictions with configurable capacity and TTL.
 * Tracks hit/miss/eviction telemetry to optimize system performance and memory footprint.
 */

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export interface CacheStats {
  size: number;
  maxSize: number;
  hits: number;
  misses: number;
  evictions: number;
  hitRatePercent: number;
}

export class LruCache<K, V> {
  private readonly maxSize: number;
  private readonly defaultTtlMs: number;
  private map = new Map<K, CacheEntry<V>>();
  private hits = 0;
  private misses = 0;
  private evictions = 0;

  constructor(options: { maxSize?: number; defaultTtlMs?: number } = {}) {
    this.maxSize = Math.max(1, options.maxSize ?? 500);
    this.defaultTtlMs = options.defaultTtlMs ?? 10 * 60 * 1000; // 10 minutes default
  }

  get(key: K): V | undefined {
    const entry = this.map.get(key);
    if (!entry) {
      this.misses++;
      return undefined;
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      this.misses++;
      return undefined;
    }

    // Refresh position in Map to mark as recently used
    this.map.delete(key);
    this.map.set(key, entry);
    this.hits++;
    return entry.value;
  }

  set(key: K, value: V, ttlMs?: number): void {
    const ttl = ttlMs ?? this.defaultTtlMs;
    const expiresAt = Date.now() + ttl;

    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.maxSize) {
      // Evict oldest entry (first item in Map iteration)
      const oldestKey = this.map.keys().next().value;
      if (oldestKey !== undefined) {
        this.map.delete(oldestKey);
        this.evictions++;
      }
    }

    this.map.set(key, { value, expiresAt });
  }

  has(key: K): boolean {
    const entry = this.map.get(key);
    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return false;
    }
    return true;
  }

  delete(key: K): boolean {
    return this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
  }

  getStats(): CacheStats {
    // Purge expired entries on stats inspection
    const now = Date.now();
    for (const [key, entry] of this.map.entries()) {
      if (now > entry.expiresAt) {
        this.map.delete(key);
      }
    }

    const totalRequests = this.hits + this.misses;
    const hitRatePercent = totalRequests > 0
      ? Math.round((this.hits / totalRequests) * 10000) / 100
      : 0;

    return {
      size: this.map.size,
      maxSize: this.maxSize,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      hitRatePercent,
    };
  }
}
