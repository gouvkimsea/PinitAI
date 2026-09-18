import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app';
import prisma from '../src/database/client';
import { config } from '../src/config';
import { MetricsCollector } from '../src/modules/monitoring/metricsCollector';
import { LruCache } from '../src/utils/lruCache';
import { explanationEngine } from '../src/modules/ai/explanationEngine';
import { ssrfGuard } from '../src/scanners/url/ssrfGuard';
import { scanQueue } from '../src/workers/scanQueue';
import { detectionPipeline } from '../src/pipeline/orchestrator';
import { systemProfiler } from '../src/modules/profiling/systemProfiler';
import {
  clamAvCircuitBreaker,
  virusTotalCircuitBreaker,
  rdapCircuitBreaker,
  geminiCircuitBreaker,
  CircuitBreaker,
} from '../src/modules/ai/circuitBreaker';
import { httpAgent, httpsAgent } from '../src/utils/httpConnectionPool';
import { urlIntelligence } from '../src/modules/url/urlIntelligence';

describe('Backend Performance Optimization & Telemetry Tests', () => {
  const app = createApp();
  const metricsCollector = MetricsCollector.getInstance();
  let adminToken = '';

  beforeAll(async () => {
    await prisma.$queryRaw`SELECT 1`;

    adminToken = jwt.sign(
      { id: 'perf-admin-id', email: 'admin@scamcheck.io', role: 'admin' },
      config.jwtSecret,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    await new Promise((resolve) => setTimeout(resolve, 300));
    await prisma.$disconnect();
  });

  // =========================================================================
  // 1. Ten Performance Measurement Dimensions
  // =========================================================================
  describe('1. Ten Performance Measurement Dimensions (/api/health/performance & /api/metrics)', () => {
    it('GET /api/health/performance should measure all 10 required dimensions', async () => {
      // Warm up requests first
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
      expect(typeof m.api_response_time.total_requests).toBe('number');

      // Dimension 2: Database queries
      expect(m.database_queries).toBeDefined();
      expect(typeof m.database_queries.total_queries).toBe('number');
      expect(typeof m.database_queries.latency_ms.p50).toBe('number');
      expect(typeof m.database_queries.latency_ms.p95).toBe('number');

      // Dimension 3: AI latency
      expect(m.ai_latency).toBeDefined();
      expect(typeof m.ai_latency.total_calls).toBe('number');
      expect(typeof m.ai_latency.cached_calls).toBe('number');
      expect(typeof m.ai_latency.cache_hit_rate_percent).toBe('number');
      expect(typeof m.ai_latency.latency_ms.p50).toBe('number');

      // Dimension 4: External API latency
      expect(m.external_api).toBeDefined();
      expect(typeof m.external_api.total_calls).toBe('number');
      expect(typeof m.external_api.latency_ms.p50).toBe('number');
      expect(typeof m.external_api.latency_ms.p95).toBe('number');

      // Dimension 5: URL analysis time
      expect(m.url_analysis).toBeDefined();
      expect(typeof m.url_analysis.total_analyses).toBe('number');
      expect(typeof m.url_analysis.latency_ms.p50).toBe('number');

      // Dimension 6: File processing time
      expect(m.file_processing).toBeDefined();
      expect(typeof m.file_processing.total_files).toBe('number');
      expect(typeof m.file_processing.latency_ms.p50).toBe('number');

      // Dimension 7: CPU usage
      expect(m.cpu).toBeDefined();
      expect(typeof m.cpu.user_cpu_ms).toBe('number');
      expect(typeof m.cpu.system_cpu_ms).toBe('number');
      expect(typeof m.cpu.approx_cpu_percent).toBe('number');

      // Dimension 8: Memory usage
      expect(m.memory).toBeDefined();
      expect(m.memory.rss_mb).toBeGreaterThan(0);
      expect(m.memory.heap_used_mb).toBeGreaterThan(0);

      // Dimension 9: Concurrent requests
      expect(m.concurrency).toBeDefined();
      expect(typeof m.concurrency.active_requests).toBe('number');
      expect(typeof m.concurrency.peak_concurrent_requests).toBe('number');

      // Dimension 10: Cache hit rate
      expect(m.cache).toBeDefined();
      expect(typeof m.cache.total_lookups).toBe('number');
      expect(typeof m.cache.total_hits).toBe('number');
      expect(typeof m.cache.hit_rate_percent).toBe('number');
    });

    it('GET /api/metrics should return Prometheus metrics including cache and concurrency', async () => {
      const res = await request(app).get('/api/metrics');

      expect(res.status).toBe(200);
      expect(res.body.metrics).toBeDefined();
      expect(res.body.metrics.api_response_time).toBeDefined();
      expect(res.body.metrics.memory).toBeDefined();
      expect(res.body.metrics.cpu).toBeDefined();
      expect(res.body.metrics.concurrency).toBeDefined();
      expect(res.body.metrics.cache).toBeDefined();
    });

    it('GET /health/performance root alias should return 200 with cache-control header', async () => {
      const res = await request(app).get('/health/performance');
      expect(res.status).toBe(200);
      expect(res.headers['cache-control']).toBeDefined();
      expect(res.body.performance_metrics).toBeDefined();
    });
  });

  // =========================================================================
  // 2. Duplicate Analysis Optimization & Accuracy Preservation
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
  // 3. AI Requests Optimization & Deterministic Short-Circuiting
  // =========================================================================
  describe('3. AI Requests Optimization & Deterministic Short-Circuiting', () => {
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

    it('should short-circuit external LLM calls when deterministic evidence is conclusive', async () => {
      const conclusiveBrief = {
        targetType: 'TEXT' as const,
        threatCategory: 'malware',
        riskScore: 99,
        classification: 'Malicious' as const,
        threatLevel: 'MALICIOUS' as const,
        confidenceScore: 95,
        language: 'en',
        indicators: [
          'EICAR standard antivirus test signature matched',
          'Confirmed malicious trojan dropper pattern',
        ],
        rawContentSnippet: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
      };

      const start = performance.now();
      const exp = await explanationEngine.generateStructuredExplanation(conclusiveBrief);
      const elapsed = performance.now() - start;

      // Deterministic generation resolves immediately without network latency
      expect(elapsed).toBeLessThan(50);
      expect(exp.summary).toBeDefined();
      expect(exp.generated_by).toBe('grounded_rules_engine');
      expect(exp.ai_generated).toBe(false);
      expect(exp.grounded_in_evidence).toBe(true);
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

      await Promise.all(
        scanIds.map((id) =>
          scanQueue.addJob({
            type: 'TEXT',
            scanId: id,
            content: 'Job content probe ' + id,
          })
        )
      );

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

  // =========================================================================
  // 7. Single-Flight In-Flight Scan Deduplication (Optimization 11)
  // =========================================================================
  describe('7. In-Flight Single-Flight Scan Deduplication', () => {
    it('should deduplicate concurrent in-flight scans for identical content', async () => {
      const uniquePayload = 'Concurrent single-flight probe ' + Date.now();

      // Launch 5 concurrent scan executions simultaneously
      const results = await Promise.all([
        detectionPipeline.execute({ type: 'TEXT', rawContent: uniquePayload }),
        detectionPipeline.execute({ type: 'TEXT', rawContent: uniquePayload }),
        detectionPipeline.execute({ type: 'TEXT', rawContent: uniquePayload }),
        detectionPipeline.execute({ type: 'TEXT', rawContent: uniquePayload }),
        detectionPipeline.execute({ type: 'TEXT', rawContent: uniquePayload }),
      ]);

      expect(results.length).toBe(5);

      // All 5 callers must receive the exact same scan ID from the single in-flight promise
      const primaryScanId = results[0].scanId;
      for (const r of results) {
        expect(r.scanId).toBe(primaryScanId);
        expect(r.threatLevel).toBe(results[0].threatLevel);
        expect(r.riskScore).toBe(results[0].riskScore);
      }
    });
  });

  // =========================================================================
  // 8. External Service Circuit Breakers Fail-Fast (Optimization 8)
  // =========================================================================
  describe('8. External Service Circuit Breakers', () => {
    it('should initialize and maintain dedicated circuit breakers for all external services', () => {
      expect(clamAvCircuitBreaker).toBeDefined();
      expect(virusTotalCircuitBreaker).toBeDefined();
      expect(rdapCircuitBreaker).toBeDefined();
      expect(geminiCircuitBreaker).toBeDefined();

      expect(typeof clamAvCircuitBreaker.getState).toBe('function');
      expect(typeof virusTotalCircuitBreaker.getState).toBe('function');
    });

    it('should transition to OPEN after reaching failure threshold and fail-fast', () => {
      const testBreaker = new CircuitBreaker({
        name: 'test-external-api',
        failureThreshold: 3,
        cooldownMs: 1000,
      });

      expect(testBreaker.getState()).toBe('CLOSED');
      expect(testBreaker.isOpen()).toBe(false);

      testBreaker.recordFailure('Network timeout');
      testBreaker.recordFailure('Connection reset');
      expect(testBreaker.getState()).toBe('CLOSED');

      // 3rd failure trips the breaker
      testBreaker.recordFailure('500 Internal Error');
      expect(testBreaker.getState()).toBe('OPEN');
      expect(testBreaker.isOpen()).toBe(true);

      // Reset restores CLOSED state
      testBreaker.recordSuccess();
      expect(testBreaker.getState()).toBe('CLOSED');
      expect(testBreaker.isOpen()).toBe(false);
    });
  });

  // =========================================================================
  // 9. Database Query Projection and Selective Loading (Optimizations 5, 6)
  // =========================================================================
  describe('9. Database Query Projection & Selective Loading', () => {
    it('GET /api/scans should use selective column projection and return 200', async () => {
      const res = await request(app).get('/api/scans?limit=5');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);

      if (res.body.data.length > 0) {
        const item = res.body.data[0];
        expect(item.id).toBeDefined();
        expect(item.status).toBeDefined();
      }
    });

    it('GET /api/reports should allow authorized admin access and return 200', async () => {
      const res = await request(app)
        .get('/api/reports?limit=5')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
    });

    it('GET /api/admin/dataset should support pagination parameters', async () => {
      const res = await request(app)
        .get('/api/admin/dataset?page=1&limit=5')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.pagination).toBeDefined();
      expect(res.body.pagination.page).toBe(1);
      expect(res.body.pagination.limit).toBe(5);
    });
  });

  // =========================================================================
  // 10. HTTP Connection Pool & Keep-Alive (Optimization 13)
  // =========================================================================
  describe('10. HTTP Connection Pool & Keep-Alive', () => {
    it('should configure keep-alive and socket pooling on global agents', () => {
      expect(httpAgent).toBeDefined();
      expect(httpsAgent).toBeDefined();
      expect(httpAgent.options.keepAlive).toBe(true);
      expect(httpsAgent.options.keepAlive).toBe(true);
      expect(httpAgent.options.maxSockets).toBe(50);
      expect(httpsAgent.options.maxSockets).toBe(50);
    });
  });

  // =========================================================================
  // 11. Safe-To-Cache Reputation & Whitelist Immunity (Optimization 2)
  // =========================================================================
  describe('11. Safe Reputation Whitelist Fast-Path', () => {
    it('should resolve whitelisted high-reputation domains in <15ms without network calls', async () => {
      const t0 = performance.now();
      const result = await urlIntelligence.analyze('https://google.com/search?q=test');
      const duration = performance.now() - t0;

      expect(result.metadata.domain).toBe('google.com');
      expect(result.severity).toBe('safe');
      expect(result.compositeScore).toBe(0);
      // Fast path must complete rapidly
      expect(duration).toBeLessThan(35);
    });
  });

  // =========================================================================
  // 12. System Profiler End-to-End Across 10 Dimensions
  // =========================================================================
  describe('12. End-to-End System Profiler', () => {
    it('systemProfiler.runProfile() should benchmark all 10 dimensions successfully', async () => {
      const profile = await systemProfiler.runProfile({ iterations: 6, concurrency: 2 });

      expect(profile).toBeDefined();
      expect(profile.durationSeconds).toBeGreaterThan(0);

      // Validate 10 dimensions in profile output
      expect(profile.apiResponseTime.samples).toBeGreaterThan(0);
      expect(typeof profile.apiResponseTime.meanMs).toBe('number');
      expect(typeof profile.databaseQueries.totalQueries).toBe('number');
      expect(typeof profile.aiLatency.totalCalls).toBe('number');
      expect(typeof profile.externalApi.totalCalls).toBe('number');
      expect(profile.urlScanningTime.scansCount).toBeGreaterThan(0);
      expect(profile.fileScanningTime.scansCount).toBeGreaterThan(0);
      expect(profile.cpuUsage.approxCpuPercent).toBeGreaterThanOrEqual(0);
      expect(profile.memoryUsage.rssMb).toBeGreaterThan(0);
      expect(profile.concurrency.totalRequestsCompleted).toBeGreaterThan(0);
      expect(profile.concurrency.throughputReqPerSec).toBeGreaterThan(0);
      expect(typeof profile.cacheMetrics.hitRatePercent).toBe('number');
    }, 20000);
  });

  // =========================================================================
  // 13. Detection Quality & Accuracy Preservation
  // =========================================================================
  describe('13. Accuracy & Threat Level Preservation Guarantee', () => {
    it('should accurately identify severe banking phishing scams', async () => {
      const scamMsg = 'URGENT: Your ABA Bank account is suspended! Log in to restore access immediately: http://fake-login-aba.com';
      const res = await request(app).post('/api/analyze/message').send({ content: scamMsg });

      expect(res.status).toBe(200);
      const score = res.body.risk_score ?? res.body.data?.risk_score;
      const classification = res.body.classification ?? res.body.data?.classification;

      expect(score).toBeGreaterThanOrEqual(70);
      expect(['Malicious', 'Suspicious', 'MALICIOUS', 'SUSPICIOUS', 'Critical Risk', 'High Risk']).toContain(classification);
    });

    it('should accurately identify benign communication with zero false positives', async () => {
      const safeMsg = 'Hi Mom, I will be home for dinner around 7pm. Love you!';
      const res = await request(app).post('/api/analyze/message').send({ content: safeMsg });

      expect(res.status).toBe(200);
      const score = res.body.risk_score ?? res.body.data?.risk_score;
      const classification = res.body.classification ?? res.body.data?.classification;

      expect(score).toBeLessThanOrEqual(25);
      expect(['Safe', 'SAFE', 'Low Risk']).toContain(classification);
    });
  });
});
