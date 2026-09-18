import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import {
  evaluationEngine,
  getBenchmarkDataset,
  validateDatasetIntegrity,
  getSamplesByLanguage,
  getSamplesByTag,
} from '../src/modules/evaluation';

describe('Systematic Scam Detection Evaluation & Quality Benchmark', () => {
  const app = createApp();

  // ──────────────────────────────────────────────────────────────────────────
  // 1. Dataset Integrity & Balance Verification
  // ──────────────────────────────────────────────────────────────────────────
  describe('1. Dataset Integrity & Balance', () => {
    it('should validate complete dataset integrity, uniqueness, and balance ratio', () => {
      const integrity = validateDatasetIntegrity();

      expect(integrity.isValid).toBe(true);
      expect(integrity.errors).toEqual([]);
      expect(integrity.total).toBeGreaterThanOrEqual(40);

      // Verify balanced distribution: Scam ratio between 40% and 60%
      const scamRatio = integrity.scamCount / integrity.total;
      expect(scamRatio).toBeGreaterThanOrEqual(0.4);
      expect(scamRatio).toBeLessThanOrEqual(0.6);

      // All 3 language variants present
      expect(integrity.languagesCovered).toContain('en');
      expect(integrity.languagesCovered).toContain('km');
      expect(integrity.languagesCovered).toContain('km-en');
    });

    it('should cover all 16 required scam categories', () => {
      const integrity = validateDatasetIntegrity();
      const requiredScamCategories = [
        'phishing',
        'fake_banking',
        'fake_payment',
        'fake_job',
        'fake_investment',
        'fake_shopping',
        'fake_delivery',
        'fake_prize',
        'fake_loan',
        'romance_scam',
        'impersonation',
        'account_takeover',
        'otp_theft',
        'credential_theft',
        'malicious_download',
        'qr_scam',
      ];

      for (const cat of requiredScamCategories) {
        expect(
          integrity.scamCategoriesCovered,
          `Missing required scam category: ${cat}`
        ).toContain(cat);
      }
    });

    it('should cover all 10 required legitimate categories', () => {
      const integrity = validateDatasetIntegrity();
      const requiredLegitCategories = [
        'bank_message',
        'delivery_message',
        'job_advertisement',
        'shopping_website',
        'payment_instructions',
        'customer_support',
        'government_announcement',
        'promotional_message',
        'investment_information',
        'social_media_message',
      ];

      for (const cat of requiredLegitCategories) {
        expect(
          integrity.legitimateCategoriesCovered,
          `Missing required legitimate category: ${cat}`
        ).toContain(cat);
      }
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 2. Comprehensive Benchmark Execution & Primary Metrics
  // ──────────────────────────────────────────────────────────────────────────
  describe('2. Comprehensive Benchmark Execution & Primary Metrics', () => {
    it('should execute benchmark and meet quality gates (F1 >= 95%, FNR <= 5%, FPR <= 5%)', async () => {
      const report = await evaluationEngine.runBenchmark();

      // Basic dataset execution check
      expect(report.total).toBe(getBenchmarkDataset().length);
      expect(report.confusionMatrix.truePositives).toBeGreaterThan(0);
      expect(report.confusionMatrix.trueNegatives).toBeGreaterThan(0);

      // Accuracy threshold
      expect(report.accuracy).toBeGreaterThanOrEqual(95.0);

      // Precision threshold
      expect(report.precision).toBeGreaterThanOrEqual(95.0);

      // Recall threshold
      expect(report.recall).toBeGreaterThanOrEqual(95.0);

      // F1 Score threshold
      expect(report.f1Score).toBeGreaterThanOrEqual(95.0);

      // False-Positive Rate threshold (<= 5%)
      expect(report.falsePositiveRate).toBeLessThanOrEqual(5.0);

      // False-Negative Rate threshold (<= 5%)
      expect(report.falseNegativeRate).toBeLessThanOrEqual(5.0);
    });

    it('should satisfy production latency SLAs (mean <= 250ms, p95 <= 600ms)', async () => {
      const report = await evaluationEngine.runBenchmark();

      expect(report.latency.meanMs).toBeLessThanOrEqual(250);
      expect(report.latency.p95Ms).toBeLessThanOrEqual(600);
      expect(report.latency.medianMs).toBeGreaterThan(0);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 3. Security-Critical False Negative Monitoring
  // ──────────────────────────────────────────────────────────────────────────
  describe('3. Security-Critical False Negative Monitoring', () => {
    it('must have ZERO false negatives on high-consequence threats (OTP, credentials, malware, banking)', async () => {
      const report = await evaluationEngine.runBenchmark();

      expect(
        report.securityAudit.criticalFalseNegativesCount,
        `Critical threats slipped through undetected: ${report.securityAudit.flaggedThreatsSampleIds.join(', ')}`
      ).toBe(0);

      expect(report.securityAudit.passedSecurityGate).toBe(true);
      expect(report.securityAudit.gateFailures).toEqual([]);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 4. Multilingual Detection Parity
  // ──────────────────────────────────────────────────────────────────────────
  describe('4. Multilingual Detection Parity', () => {
    it('should achieve F1 >= 95% across English samples', async () => {
      const enSamples = getSamplesByLanguage('en');
      const report = await evaluationEngine.runBenchmark(enSamples);

      expect(report.f1Score).toBeGreaterThanOrEqual(95.0);
      expect(report.falseNegativeRate).toBeLessThanOrEqual(5.0);
    });

    it('should achieve F1 >= 95% across Khmer samples', async () => {
      const kmSamples = getSamplesByLanguage('km');
      const report = await evaluationEngine.runBenchmark(kmSamples);

      expect(report.f1Score).toBeGreaterThanOrEqual(95.0);
      expect(report.falseNegativeRate).toBeLessThanOrEqual(5.0);
    });

    it('should achieve F1 >= 95% across mixed Khmer-English samples', async () => {
      const mixSamples = getSamplesByLanguage('km-en');
      const report = await evaluationEngine.runBenchmark(mixSamples);

      expect(report.f1Score).toBeGreaterThanOrEqual(95.0);
      expect(report.falseNegativeRate).toBeLessThanOrEqual(5.0);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 5. Nuanced Edge Cases (Slang, Misspellings, Shorteners, Unusual Domains)
  // ──────────────────────────────────────────────────────────────────────────
  describe('5. Nuanced Edge Cases', () => {
    it('should correctly classify informal social messages with slang and misspellings as legitimate', async () => {
      const slangLegitSamples = getSamplesByTag('slang_shorthand').filter(
        (s) => s.expectedLabel === 'LEGITIMATE'
      );

      for (const sample of slangLegitSamples) {
        const result = await evaluationEngine.evaluateSample(sample);
        expect(
          result.predictedLabel,
          `Slang/informal legitimate sample incorrectly flagged as scam: ${sample.id} (${sample.content})`
        ).toBe('LEGITIMATE');
      }
    });

    it('should catch adversarial scams employing slang and misspellings', async () => {
      const slangScamSamples = getSamplesByTag('slang_shorthand').filter(
        (s) => s.expectedLabel === 'SCAM'
      );

      for (const sample of slangScamSamples) {
        const result = await evaluationEngine.evaluateSample(sample);
        expect(
          result.predictedLabel,
          `Adversarial scam with slang/misspellings missed: ${sample.id} (${sample.content})`
        ).toBe('SCAM');
      }
    });

    it('should NOT produce false positives on legitimate shortened URLs or unusual official domains', async () => {
      const unusualLegitSamples = [
        ...getSamplesByTag('legitimate_shortener'),
        ...getSamplesByTag('unusual_domain').filter((s) => s.expectedLabel === 'LEGITIMATE'),
        ...getSamplesByTag('long_url').filter((s) => s.expectedLabel === 'LEGITIMATE'),
      ];

      for (const sample of unusualLegitSamples) {
        const result = await evaluationEngine.evaluateSample(sample);
        expect(
          result.predictedLabel,
          `Legitimate sample with unusual domain or URL incorrectly flagged: ${sample.id}`
        ).toBe('LEGITIMATE');
      }
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 6. HTTP API Integration (/api/evaluation/*)
  // ──────────────────────────────────────────────────────────────────────────
  describe('6. HTTP API Integration (/api/evaluation/*)', () => {
    it('GET /api/evaluation/dataset should return dataset metadata and sample lists', async () => {
      const res = await request(app).get('/api/evaluation/dataset');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.integrity.isValid).toBe(true);
      expect(res.body.filteredCount).toBeGreaterThanOrEqual(40);
      expect(Array.isArray(res.body.samples)).toBe(true);
    });

    it('GET /api/evaluation/dataset should support category and language filtering', async () => {
      const res = await request(app)
        .get('/api/evaluation/dataset')
        .query({ language: 'km', label: 'SCAM' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.filteredCount).toBeGreaterThan(0);
      for (const sample of res.body.samples) {
        expect(sample.language).toBe('km');
        expect(sample.expectedLabel).toBe('SCAM');
      }
    });

    it('POST /api/evaluation/benchmark should execute benchmark and return complete report', async () => {
      const res = await request(app).post('/api/evaluation/benchmark');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accuracy).toBeGreaterThanOrEqual(95.0);
      expect(res.body.data.f1Score).toBeGreaterThanOrEqual(95.0);
      expect(res.body.data.falseNegativeRate).toBeLessThanOrEqual(5.0);
      expect(res.body.data.securityAudit.passedSecurityGate).toBe(true);
    });

    it('POST /api/evaluation/benchmark?format=markdown should format report as Markdown', async () => {
      const res = await request(app)
        .post('/api/evaluation/benchmark')
        .query({ format: 'markdown' });

      expect(res.status).toBe(200);
      expect(res.text).toContain('# Pinit Scam Detection Quality Benchmark Report');
      expect(res.text).toContain('Overall Performance Summary');
      expect(res.text).toContain('Confusion Matrix');
    });

    it('GET /api/evaluation/metrics should retrieve current metrics', async () => {
      const res = await request(app).get('/api/evaluation/metrics');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.total).toBeGreaterThanOrEqual(40);
    });
  });
});
