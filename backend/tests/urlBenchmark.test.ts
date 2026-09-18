import { describe, it, expect } from 'vitest';
import { urlBenchmarkEvaluator, BENCHMARK_DATASET } from '../src/modules/url/urlMetrics';

describe('URL Detection Engine Benchmark & False Positive / Negative Measurements', () => {
  it('should run benchmark against balanced dataset of legitimate and malicious URLs', async () => {
    const results = await urlBenchmarkEvaluator.runBenchmark(BENCHMARK_DATASET);

    // Verify benchmark structure
    expect(results.total).toBe(BENCHMARK_DATASET.length);
    expect(results.total).toBeGreaterThanOrEqual(25);
    expect(results.truePositives).toBeGreaterThan(0);
    expect(results.trueNegatives).toBeGreaterThan(0);

    // Assert False Positive Rate is low (< 5%)
    expect(results.falsePositiveRate).toBeLessThanOrEqual(5.0);

    // Assert False Negative Rate is low (< 5%)
    expect(results.falseNegativeRate).toBeLessThanOrEqual(5.0);

    // Assert overall accuracy is >= 95%
    expect(results.accuracy).toBeGreaterThanOrEqual(95.0);

    // Assert precision is >= 95%
    expect(results.precision).toBeGreaterThanOrEqual(95.0);

    // Assert recall is >= 95%
    expect(results.recall).toBeGreaterThanOrEqual(95.0);
  });

  it('should never produce a false positive on prominent authentic domains', async () => {
    const authenticWebsites = [
      'https://www.google.com',
      'https://github.com',
      'https://en.wikipedia.org',
      'https://www.microsoft.com',
      'https://apple.com',
      'https://www.paypal.com/signin',
      'https://www.ababank.com/personal-banking/',
      'https://www.acledabank.com.kh/kh/eng/',
      'https://wingmoney.com/en/personal/',
      'https://tax.gov.kh/en/',
      'https://cambodiapost.post/',
    ];

    for (const url of authenticWebsites) {
      const { urlIntelligence } = await import('../src/modules/url/urlIntelligence');
      const res = await urlIntelligence.analyze(url, { skipNetworkProbe: true });
      expect(res.compositeScore).toBeLessThanOrEqual(30);
      expect(res.severity).not.toBe('critical');
      expect(res.severity).not.toBe('high');
    }
  });

  it('should reliably catch deceptive lookalikes and fake financial domains', async () => {
    const dangerousWebsites = [
      'https://paypa1.com/signin',
      'https://paypai.com/account/login',
      'https://paypal-security-verification.com/login',
      'https://ababank-verify.com/portal/login',
      'https://wing-security-update.xyz/login',
      'https://acledabank-online.net/auth',
      'https://canadiabank-verify.site/signin',
      'https://cambodiapost-fee-tracking.com/pay',
      'https://dhl-parcel-delivery.xyz/tracking/redelivery',
      'https://fileshare-portal.com/invoices/payment_slip.exe',
      'http://45.33.32.156/portal/login',
    ];

    for (const url of dangerousWebsites) {
      const { urlIntelligence } = await import('../src/modules/url/urlIntelligence');
      const res = await urlIntelligence.analyze(url, { skipNetworkProbe: true });
      expect(res.compositeScore).toBeGreaterThanOrEqual(40);
      expect(['medium', 'high', 'critical']).toContain(res.severity);
    }
  });
});
