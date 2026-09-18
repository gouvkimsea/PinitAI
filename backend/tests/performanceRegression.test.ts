import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import prisma from '../src/database/client';
import { threatIntel } from '../src/scanners/threatIntel/threatIntelProvider';
import { detectionPipeline } from '../src/pipeline/orchestrator';
import { evaluationEngine } from '../src/modules/evaluation';

describe('PinIt Performance Regression & Latency Budget Test Suite', () => {
  const app = createApp();

  beforeEach(async () => {
    detectionPipeline.clearCache();
  });

  describe('1. Caching & Single-Flight Deduplication Latency Budgets', () => {
    it('cached scan lookups must return within 60ms end-to-end HTTP budget', async () => {
      const payload = { content: 'Performance regression cache test message' };

      // Initial prime
      const primeRes = await request(app)
        .post('/api/analyze/text')
        .send(payload)
        .set('Accept', 'application/json');
      expect(primeRes.status).toBe(200);

      // Cached hit
      const start = Date.now();
      const cachedRes = await request(app)
        .post('/api/analyze/text')
        .send(payload)
        .set('Accept', 'application/json');
      const durationMs = Date.now() - start;

      expect(cachedRes.status).toBe(200);
      expect(cachedRes.body.cached).toBe(true);
      expect(durationMs).toBeLessThanOrEqual(60); // strict HTTP test runner budget
    });

    it('concurrent identical requests must be deduplicated via single-flight mechanism', async () => {
      const payload = { content: 'Concurrent deduplication performance regression test' };
      const start = Date.now();

      const responses = await Promise.all([
        request(app).post('/api/analyze/text').send(payload),
        request(app).post('/api/analyze/text').send(payload),
        request(app).post('/api/analyze/text').send(payload),
      ]);

      const durationMs = Date.now() - start;
      for (const res of responses) {
        expect(res.status).toBe(200);
      }
      // Single-flight avoids running 3 independent full pipeline cycles
      expect(durationMs).toBeLessThan(400);
    });
  });

  describe('2. Negative Reputation Caching', () => {
    it('clean domain reputation lookups are persisted and served from cache', async () => {
      const cleanDomain = 'safe-clean-example-test.org';

      // 1st lookup: evaluates providers and negative caches
      const start1 = Date.now();
      const res1 = await threatIntel.checkDomain(cleanDomain);
      const dur1 = Date.now() - start1;
      expect(res1).toBeNull();

      // 2nd lookup: served from memory cache immediately (0-15ms)
      const start2 = Date.now();
      const res2 = await threatIntel.checkDomain(cleanDomain);
      const dur2 = Date.now() - start2;
      expect(res2).toBeNull();
      expect(dur2).toBeLessThanOrEqual(15);

      // Verify negative cache entry exists in DB
      const dbEntry = await prisma.threatIntelligence.findFirst({
        where: {
          targetType: 'DOMAIN',
          targetValue: cleanDomain,
          threatCategory: 'CLEAN',
        },
      });
      expect(dbEntry).not.toBeNull();
      expect(dbEntry?.reputationScore).toBe(0);
    });
  });

  describe('3. Database Query & Field Projection Optimization', () => {
    it('paginated scan query returns within 80ms without N+1 joins', async () => {
      const start = Date.now();
      const res = await request(app)
        .get('/api/v1/scans?page=1&limit=10')
        .set('Accept', 'application/json');
      const durationMs = Date.now() - start;

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(durationMs).toBeLessThanOrEqual(80);
    });
  });

  describe('4. Detection Accuracy Invariant (Zero Regression)', () => {
    it('critical phishing signals and risk level remain 100% accurate', async () => {
      const scamMessage = 'Urgent: Your bank account has been suspended. Verify credentials at http://phishing-test-login.com immediately.';
      const res = await request(app)
        .post('/api/analyze/text')
        .send({ content: scamMessage })
        .set('Accept', 'application/json');

      expect(res.status).toBe(200);
      expect(res.body.threat_level).toMatch(/HIGH_RISK|MALICIOUS|CRITICAL/);
      expect(res.body.risk_score).toBeGreaterThanOrEqual(60);
      expect(res.body.signals.length).toBeGreaterThan(0);
    });

    it('verified benchmark accuracy score remains high without false positives', async () => {
      const sample = {
        id: 'perf-test-benign',
        targetType: 'TEXT' as const,
        content: 'Hi Sarah, are we still meeting for lunch today at noon?',
        expectedLabel: 'LEGITIMATE' as const,
        language: 'en' as const,
        category: 'normal_message',
        difficulty: 'obvious' as const,
        nuanceTags: [],
        description: 'Benign conversational lunch reminder',
      };

      const result = await evaluationEngine.evaluateSample(sample);
      expect(result.predictedLabel).toBe('LEGITIMATE');
      expect(result.isCorrect).toBe(true);
      expect(result.score).toBeLessThan(30);
    });
  });
});
