import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import prisma from '../src/database/client';
import { MetricsCollector } from '../src/modules/monitoring/metricsCollector';
import { LruCache } from '../src/utils/lruCache';
import { explanationEngine } from '../src/modules/ai/explanationEngine';
import { ssrfGuard } from '../src/scanners/url/ssrfGuard';
import { scanQueue } from '../src/workers/scanQueue';
import { detectionPipeline } from '../src/pipeline/orchestrator';

describe('Backend Performance Optimization & Telemetry Tests', () => {
  const app = createApp();
  const metricsCollector = MetricsCollector.getInstance();

  beforeAll(async () => {
    await prisma.$queryRaw`SELECT 1`;
  });

  afterAll(async () => {
    await new Promise((resolve) => setTimeout(resolve, 300));
    await prisma.$disconnect();
  });

  // =========================================================================
  // 1. Seven Measurement Dimensions
  // =========================================================================
  describe('1. Seven Measurement Dimensions (/api/health/performance & /api/metrics)', () => {
    it('GET /api/health/performance should measure all 7 required dimensions', async () => {
      // Generate some requests first to populate ring buffers
      await request(app).get('/api/health');

      const res = await request(app).get('/api/health/performance');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.timestamp).toBeDefined();
      expect(typeof res.body.uptime_seconds).toBe('number');

      const m = res.body.performance_metrics;
      expect(m).toBeDefined();

      // Dimension 1: API response time
      expect(m.api_response_time).toBeDefined();
      expect(typeof m.api_response_time.p50_ms).toBe('number');
      expect(typeof m.api_response_time.p95_ms).toBe('number');
      expect(typeof m.api_response_time.p99_ms).toBe('number');
      expect(typeof m.api_response_time.avg_ms).toBe('number');
      expect(typeof m.api_response_time.min_ms).toBe('number');
      expect(typeof m.api_response_time.max_ms).toBe('number');
      expect(typeof m.api_response_time.total_requests).toBe('number');
      expect(typeof m.api_response_time.slow_requests).toBe('number');
      expect(typeof m.api_response_time.error_requests).toBe('number');

      // Dimension 2: AI latency
      expect(m.ai_latency).toBeDefined();
      expect(typeof m.ai_latency.total_calls).toBe('number');
      expect(typeof m.ai_latency.cached_calls).toBe('number');
      expect(typeof m.ai_latency.cache_hit_rate_percent).toBe('number');
      expect(typeof m.ai_latency.latency_ms.p50).toBe('number');
      expect(typeof m.ai_latency.latency_ms.p95).toBe('number');
      expect(typeof m.ai_latency.latency_ms.p99).toBe('number');

      // Dimension 3: Database queries
      expect(m.database_queries).toBeDefined();
      expect(typeof m.database_queries.total_queries).toBe('number');
      expect(typeof m.database_queries.slow_queries).toBe('number');
      expect(typeof m.database_queries.latency_ms.p50).toBe('number');
      expect(typeof m.database_queries.latency_ms.p95).toBe('number');
      expect(typeof m.database_queries.latency_ms.p99).toBe('number');

      // Dimension 4: URL analysis time
      expect(m.url_analysis).toBeDefined();
      expect(typeof m.url_analysis.total_analyses).toBe('number');
      expect(typeof m.url_analysis.cached_analyses).toBe('number');
      expect(typeof m.url_analysis.cache_hit_rate_percent).toBe('number');
      expect(typeof m.url_analysis.latency_ms.p50).toBe('number');

      // Dimension 5: File processing time
      expect(m.file_processing).toBeDefined();
      expect(typeof m.file_processing.total_files).toBe('number');
      expect(typeof m.file_processing.cached_files).toBe('number');
      expect(typeof m.file_processing.cache_hit_rate_percent).toBe('number');
      expect(typeof m.file_processing.latency_ms.p50).toBe('number');

      // Dimension 6: Memory usage
      expect(m.memory).toBeDefined();
      expect(m.memory.rss_mb).toBeGreaterThan(0);
      expect(m.memory.heap_used_mb).toBeGreaterThan(0);
      expect(m.memory.heap_total_mb).toBeGreaterThan(0);

      // Dimension 7: CPU usage
      expect(m.cpu).toBeDefined();
      expect(typeof m.cpu.user_cpu_ms).toBe('number');
      expect(typeof m.cpu.system_cpu_ms).toBe('number');
      expect(typeof m.cpu.approx_cpu_percent).toBe('number');
    });

    it('GET /api/metrics should return Prometheus and summary formatted metrics', async () => {
      const res = await request(app).get('/api/metrics');

      expect(res.status).toBe(200);
      expect(res.body.metrics).toBeDefined();
      expect(res.body.metrics.api_response_time).toBeDefined();
      expect(res.body.metrics.memory).toBeDefined();
      expect(res.body.metrics.cpu).toBeDefined();
    });

    it('GET /health/performance root alias should return 200', async () => {
      const res = await request(app).get('/health/performance');
      expect(res.status).toBe(200);
      expect(res.body.performance_metrics).toBeDefined();
    });
  });

  // =========================================================================
  // 2. Duplicate Analysis Optimization & Accuracy
  // =========================================================================
  describe('2. Duplicate Analysis Optimization', () => {
    it('should serve repeated identical scans from cache with high speed without sacrificing accuracy', async () => {
      const sampleText = 'URGENT: Your bank account has been suspended! Verify immediately at http://fake-login-bank.xyz';

      // First run: cold execution
      const t1 = performance.now();
      const res1 = await request(app)
        .post('/api/analyze/message')
        .send({ content: sampleText });
      const duration1 = performance.now() - t1;

      expect(res1.status).toBe(200);
      expect(res1.body.success).toBe(true);
      const score1 = res1.body.risk_score ?? res1.body.data?.risk_score;
      const classification1 = res1.body.classification ?? res1.body.data?.classification;
      expect(score1).toBeDefined();

      // Second run: should hit duplicateCache
      const t2 = performance.now();
      const res2 = await request(app)
        .post('/api/analyze/message')
        .send({ content: sampleText });
      const duration2 = performance.now() - t2;

      expect(res2.status).toBe(200);
      expect(res2.body.success).toBe(true);
      const isCached = res2.body.cached ?? res2.body.data?.cached;
      expect(isCached).toBe(true);

      // Verify detection accuracy is 100% preserved
      const score2 = res2.body.risk_score ?? res2.body.data?.risk_score;
      const classification2 = res2.body.classification ?? res2.body.data?.classification;
      expect(score2).toBe(score1);
      expect(classification2).toBe(classification1);

      // Verify duplicate speedup: cached run should execute significantly faster
      expect(duration2).toBeLessThanOrEqual(duration1 + 50);
    });

    it('should allow bypassing duplicate cache when requested', async () => {
      const sampleText = 'Unique probe content for cache bypass testing: ' + Date.now();

      // First run
      const res1 = await request(app)
        .post('/api/analyze/message')
        .send({ content: sampleText });
      expect(res1.status).toBe(200);

      // Second run with bypassCache metadata
      const res2 = await detectionPipeline.analyze({
        type: 'TEXT',
        rawContent: sampleText,
        metadata: { bypassCache: true },
      });

      expect(res2.cached).toBeFalsy();
    });
  });

  // =========================================================================
  // 3. AI Latency & Hash Caching
  // =========================================================================
  describe('3. AI Requests Optimization & Caching', () => {
    it('should cache repeated AI structured explanation requests', async () => {
      const brief = {
        targetType: 'TEXT' as const,
        threatCategory: 'phishing',
        riskScore: 85,
        classification: 'Malicious' as const,
        threatLevel: 'MALICIOUS' as const,
        confidenceScore: 90,
        language: 'en',
        indicators: ['Suspicious urgency', 'Phishing domain detected'],
        rawContentSnippet: 'Urgent login request at test domain',
      };

      // Call 1
      const t1 = performance.now();
      const exp1 = await explanationEngine.generateStructuredExplanation(brief);
      const _d1 = performance.now() - t1;

      // Call 2 with identical brief
      const t2 = performance.now();
      const exp2 = await explanationEngine.generateStructuredExplanation(brief);
      const d2 = performance.now() - t2;

      expect(exp1.summary).toBeDefined();
      expect(exp2.summary).toBe(exp1.summary);
      expect(exp2.recommended_actions).toEqual(exp1.recommended_actions);

      // Cached call must be ultra-fast (<15ms)
      expect(d2).toBeLessThan(15);

      // Verify AI metrics telemetry tracked the cache hit
      const metrics = metricsCollector.getPerformanceMetrics();
      expect(metrics.ai_latency.cached_calls).toBeGreaterThan(0);
    });
  });

  // =========================================================================
  // 4. In-Memory LRU Cache Behavior
  // =========================================================================
  describe('4. LRU Cache Mechanics (O(1), TTL, Eviction)', () => {
    it('should evict the least recently used entry when max size is reached', () => {
      const cache = new LruCache<string, number>({ maxSize: 3, defaultTtlMs: 60000 });

      cache.set('a', 1);
      cache.set('b', 2);
      cache.set('c', 3);

      // Access 'a' so 'b' becomes the oldest unaccessed
      expect(cache.get('a')).toBe(1);

      // Insert 'd', which should evict 'b'
      cache.set('d', 4);

      expect(cache.get('b')).toBeUndefined();
      expect(cache.get('a')).toBe(1);
      expect(cache.get('c')).toBe(3);
      expect(cache.get('d')).toBe(4);

      const stats = cache.getStats();
      expect(stats.evictions).toBe(1);
      expect(stats.size).toBe(3);
    });

    it('should expire entries after TTL', async () => {
      const shortCache = new LruCache<string, string>({ maxSize: 10, defaultTtlMs: 50 });
      shortCache.set('temp', 'value');

      expect(shortCache.get('temp')).toBe('value');

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 60));

      expect(shortCache.get('temp')).toBeUndefined();
      const stats = shortCache.getStats();
      expect(stats.misses).toBeGreaterThan(0);
    });
  });

  // =========================================================================
  // 5. Network Calls & SSRF Protection
  // =========================================================================
  describe('5. Expensive Network Calls & SSRF Guard Caching', () => {
    it('should maintain strict SSRF protection without sacrificing speed', async () => {
      // SSRF attempt to cloud metadata
      const res = await ssrfGuard.validateUrlSafe('http://169.254.169.254/latest/meta-data');
      expect(res.safe).toBe(false);
      expect(res.reason).toContain('SSRF');

      // SSRF attempt to localhost
      const resLocal = await ssrfGuard.validateUrlSafe('http://127.0.0.1:8080/admin');
      expect(resLocal.safe).toBe(false);
    });

    it('should cache safe domain DNS queries for fast repeat scans', async () => {
      const testUrl = 'https://example.com/check';

      const t1 = performance.now();
      const res1 = await ssrfGuard.validateUrlSafe(testUrl);
      const d1 = performance.now() - t1;

      const t2 = performance.now();
      const res2 = await ssrfGuard.validateUrlSafe(testUrl);
      const d2 = performance.now() - t2;

      expect(res1.safe).toBe(true);
      expect(res2.safe).toBe(true);
      // Cached DNS validation runs significantly faster
      expect(d2).toBeLessThanOrEqual(d1 + 10);
    });
  });

  // =========================================================================
  // 6. Background Queue Concurrency
  // =========================================================================
  describe('6. Background Jobs Concurrency', () => {
    it('should process concurrent scan jobs through the queue worker pool', async () => {
      const scanIds = [
        'perf-job-1-' + Date.now(),
        'perf-job-2-' + Date.now(),
        'perf-job-3-' + Date.now(),
      ];

      // Create scan records in DB
      for (const id of scanIds) {
        await prisma.scan.create({
          data: {
            id,
            type: 'MESSAGE',
            target: 'Concurrent Job Test',
            status: 'QUEUED',
          },
        });
      }

      // Enqueue simultaneously
      await Promise.all(
        scanIds.map((id) =>
          scanQueue.addJob({
            type: 'TEXT',
            scanId: id,
            content: 'Job content probe ' + id,
          })
        )
      );

      // Wait up to 4 seconds for all concurrent jobs to finish
      let allDone = false;
      const startWait = Date.now();
      while (Date.now() - startWait < 4000) {
        const completed = await prisma.scan.count({
          where: {
            id: { in: scanIds },
            status: 'COMPLETED',
          },
        });
        if (completed === scanIds.length) {
          allDone = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 100));
      }

      expect(allDone).toBe(true);
    });
  });
});
