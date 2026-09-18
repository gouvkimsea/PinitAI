import { describe, it, expect, beforeEach, vi } from 'vitest';
import { privacySanitizer } from '../src/utils/privacySanitizer';
import { metricsCollector } from '../src/modules/monitoring/metricsCollector';
import { logger } from '../src/utils/logger';

describe('Production Observability & Privacy Sanitization', () => {
  beforeEach(() => {
    metricsCollector.reset();
  });

  describe('Privacy Sanitizer: Never Log Sensitive Credentials', () => {
    it('redacts passwords, OTP codes, bearer tokens, and API keys', () => {
      const rawText = 'My password is SuperSecret123! and my otp code is 849201. Use Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-o_gZ or api_key=ak_live_998877665544332211';
      const sanitized = privacySanitizer.sanitizeLogString(rawText);

      expect(sanitized).not.toContain('SuperSecret123!');
      expect(sanitized).not.toContain('849201');
      expect(sanitized).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(sanitized).not.toContain('ak_live_998877665544332211');
      expect(sanitized).toContain('[REDACTED_PASSWORD]');
      expect(sanitized).toContain('[REDACTED_OTP]');
      expect(sanitized).toContain('[REDACTED_AUTH_TOKEN]');
      expect(sanitized).toContain('[REDACTED_API_KEY]');
    });

    it('redacts credit card primary account numbers (PAN) and CVV codes', () => {
      const cardText = 'Payment card: 4532 0150 1234 5678 with cvv: 789 and pin 1234';
      const sanitized = privacySanitizer.sanitizeLogString(cardText);

      expect(sanitized).not.toContain('4532 0150 1234 5678');
      expect(sanitized).not.toContain('789');
      expect(sanitized).toContain('[REDACTED_PAYMENT_CARD]');
    });

    it('creates safe preview with privacy indicators without leaking full message', () => {
      const longMessage = 'Urgent bank alert: your account 1234 is locked. Go to http://scam-bank.com immediately. Password was password123. ' + 'extra content '.repeat(20);
      const preview = privacySanitizer.createSafePreview(longMessage, 50);

      expect(preview).not.toContain('password123');
      expect(preview.length).toBeLessThanOrEqual(70);
    });

    it('extracts privacy-preserving metadata with deterministic prefix hash', () => {
      const text = 'Hello, please click https://login.secure-update.xyz to verify your credentials. Call 1-800-555-0199 now.';
      const meta = privacySanitizer.extractPrivacyMetadata(text);

      expect(meta.charCount).toBe(text.length);
      expect(meta.wordCount).toBeGreaterThan(5);
      expect(meta.hasUrls).toBe(true);
      expect(meta.hasPhoneNumbers).toBe(true);
      expect(typeof meta.contentHashPrefix).toBe('string');
      expect(meta.contentHashPrefix.length).toBe(12);
    });

    it('recursively scrubs sensitive fields from log metadata objects', () => {
      const sensitiveObj = {
        userId: 'user_123',
        password: 'PlainTextPassword!',
        token: 'secret_jwt_token',
        nested: {
          otpCode: '123456',
          cvv: '999',
          safeField: 'normal_data'
        }
      };

      const scrubbed = privacySanitizer.scrubObject(sensitiveObj);
      expect(scrubbed.password).toBe('[REDACTED_SECRET]');
      expect(scrubbed.token).toBe('[REDACTED_SECRET]');
      expect(scrubbed.nested.otpCode).toBe('[REDACTED_SECRET]');
      expect(scrubbed.nested.cvv).toBe('[REDACTED_SECRET]');
      expect(scrubbed.nested.safeField).toBe('normal_data');
    });
  });

  describe('Metrics Collector: Scan Telemetry, Distributions & Health', () => {
    it('tracks scans by input type, categories, risk distribution, and confidence distribution', () => {
      metricsCollector.recordScan({
        inputType: 'TEXT',
        threatLevel: 'MALICIOUS',
        confidenceScore: 85,
        threatCategory: 'credential_harvesting'
      });
      metricsCollector.recordScan({
        inputType: 'URL',
        threatLevel: 'HIGH_RISK',
        confidenceScore: 65,
        threatCategory: 'phishing_domain'
      });
      metricsCollector.recordScan({
        inputType: 'FILE',
        threatLevel: 'SAFE',
        confidenceScore: 90
      });
      metricsCollector.recordScan({
        inputType: 'QR',
        threatLevel: 'SUSPICIOUS',
        confidenceScore: 40,
        threatCategory: 'qr_code_redirection'
      });

      const summary = metricsCollector.getSummary();

      expect(summary.scans.total_scans).toBe(4);
      expect(summary.scans.scans_by_input_type.TEXT).toBe(1);
      expect(summary.scans.scans_by_input_type.URL).toBe(1);
      expect(summary.scans.scans_by_input_type.FILE).toBe(1);
      expect(summary.scans.scans_by_input_type.QR).toBe(1);

      expect(summary.scans.risk_distribution.MALICIOUS).toBe(1);
      expect(summary.scans.risk_distribution.HIGH_RISK).toBe(1);
      expect(summary.scans.risk_distribution.SAFE).toBe(1);
      expect(summary.scans.risk_distribution.SUSPICIOUS).toBe(1);

      expect(summary.scans.confidence_distribution.high).toBe(2);
      expect(summary.scans.confidence_distribution.medium).toBe(1);
      expect(summary.scans.confidence_distribution.low).toBe(1);

      expect(summary.scans.detection_categories.credential_harvesting).toBe(1);
      expect(summary.scans.detection_categories.phishing_domain).toBe(1);
      expect(summary.scans.detection_categories.qr_code_redirection).toBe(1);
    });

    it('calculates average, p95, and p99 latencies accurately', () => {
      // Simulate 100 API latencies from 10ms to 1000ms
      for (let i = 1; i <= 100; i++) {
        metricsCollector.recordApiRequest(i * 10, 200);
      }

      const summary = metricsCollector.getSummary();
      expect(summary.api.total_requests).toBe(100);
      expect(summary.api.latency_ms.avg).toBe(505);
      expect(summary.api.latency_ms.p50).toBeGreaterThanOrEqual(500);
      expect(summary.api.latency_ms.p95).toBeGreaterThanOrEqual(950);
      expect(summary.api.latency_ms.p99).toBeGreaterThanOrEqual(990);
    });

    it('tracks false positives, false negatives, and calculates rate', () => {
      // Record 10 scans
      for (let i = 0; i < 10; i++) {
        metricsCollector.recordScan({
          inputType: 'TEXT',
          threatLevel: 'SAFE',
          confidenceScore: 90
        });
      }

      metricsCollector.recordFalsePositive();
      metricsCollector.recordFalseNegative();

      const summary = metricsCollector.getSummary();
      expect(summary.feedback.false_positives).toBe(1);
      expect(summary.feedback.false_negatives).toBe(1);
      expect(summary.feedback.false_positive_rate_percent).toBe(10);
      expect(summary.feedback.false_negative_rate_percent).toBe(10);
    });

    it('tracks cache hit and miss rates', () => {
      metricsCollector.recordCacheHit();
      metricsCollector.recordCacheHit();
      metricsCollector.recordCacheHit();
      metricsCollector.recordCacheMiss();

      const summary = metricsCollector.getSummary();
      expect(summary.cache.total_hits).toBe(3);
      expect(summary.cache.total_misses).toBe(1);
      expect(summary.cache.total_lookups).toBe(4);
      expect(summary.cache.hit_rate_percent).toBe(75);
    });

    it('tracks queue, database, and timeout failures', () => {
      metricsCollector.recordQueueEnqueued();
      metricsCollector.recordQueueEnqueued();
      metricsCollector.recordQueueFailure();

      metricsCollector.recordDbQuery(12, false); // failure
      metricsCollector.recordTimeout();

      const summary = metricsCollector.getSummary();
      expect(summary.queue.total_enqueued).toBe(2);
      expect(summary.queue.failures).toBe(1);
      expect(summary.database.failure_queries).toBe(1);
      expect(summary.api.timeout_requests).toBe(1);
    });
  });

  describe('Alert Threshold Evaluation', () => {
    it('triggers alerts for abnormal latency', () => {
      // Record slow requests
      for (let i = 0; i < 20; i++) {
        metricsCollector.recordApiRequest(3000, 200);
      }

      const alerts = metricsCollector.evaluateThresholdAlerts();
      expect(alerts.alerted).toBe(true);
      const latencyAlert = alerts.warnings.find(w => w.includes('Abnormal API latency detected'));
      expect(latencyAlert).toBeDefined();
    });

    it('triggers alerts for database failures', () => {
      metricsCollector.recordDbQuery(50, false);

      const alerts = metricsCollector.evaluateThresholdAlerts();
      expect(alerts.alerted).toBe(true);
      const dbAlert = alerts.warnings.find(w => w.includes('Database query failures detected'));
      expect(dbAlert).toBeDefined();
    });

    it('triggers alerts for external API failures when failure rate exceeds 30%', () => {
      for (let i = 0; i < 2; i++) metricsCollector.recordExternalApiCall(100, true);
      for (let i = 0; i < 4; i++) metricsCollector.recordExternalApiCall(100, false);

      const alerts = metricsCollector.evaluateThresholdAlerts();
      expect(alerts.alerted).toBe(true);
      const extAlert = alerts.warnings.find(w => w.includes('External API service failure alert'));
      expect(extAlert).toBeDefined();
    });

    it('triggers alerts for AI failures and fallbacks', () => {
      for (let i = 0; i < 3; i++) metricsCollector.recordAiCall(500, false, false, true); // AI failure
      for (let i = 0; i < 3; i++) metricsCollector.recordAiCall(500, false, true, false);  // Fallback used

      const alerts = metricsCollector.evaluateThresholdAlerts();
      expect(alerts.alerted).toBe(true);
      const aiAlert = alerts.warnings.find(w => w.includes('AI service degradation alert'));
      expect(aiAlert).toBeDefined();
    });

    it('triggers alerts for sudden changes in false-positive/negative rates', () => {
      for (let i = 0; i < 5; i++) {
        metricsCollector.recordScan({
          inputType: 'TEXT',
          threatLevel: 'SAFE',
          confidenceScore: 90
        });
      }
      metricsCollector.recordFalsePositive();

      const alerts = metricsCollector.evaluateThresholdAlerts();
      expect(alerts.alerted).toBe(true);
      const fpAlert = alerts.warnings.find(w => w.includes('Sudden surge in false-positive reports'));
      expect(fpAlert).toBeDefined();
    });
  });

  describe('Structured Logging with Correlation / Request ID', () => {
    it('trackDetection formats structured log with requestId and sanitized metadata', () => {
      const spy = vi.spyOn(logger.raw, 'info');

      logger.trackDetection({
        scanId: 'scan-obs-123',
        requestId: 'req-obs-test-999',
        inputType: 'TEXT',
        threatCategory: 'credential_harvesting',
        threatLevel: 'HIGH_RISK',
        riskScore: 85,
        confidenceScore: 88,
        detectorsRan: 3,
        durationMs: 142,
        privacyMetadata: {
          contentLength: 60,
          contentHashPrefix: 'a1b2c3d4e5f6',
          hasUrls: false,
          hasPhoneNumbers: false,
          hasCredentialsMasked: true,
          charCount: 60,
          wordCount: 8
        }
      });

      expect(spy).toHaveBeenCalled();
      const [msg, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(msg).toContain('Detection completed for scan scan-obs-123');
      expect(meta.event_type).toBe('DETECTION_COMPLETED');
      expect(meta.requestId).toBe('req-obs-test-999');
      expect(meta.threatLevel).toBe('HIGH_RISK');
      expect(meta.privacyMetadata.hasCredentialsMasked).toBe(true);
      spy.mockRestore();
    });

    it('trackExternalApiFailure records structured failure log with requestId', () => {
      const spy = vi.spyOn(logger.raw, 'warn');

      logger.trackExternalApiFailure({
        provider: 'virustotal',
        endpoint: '/api/v3/urls',
        error: 'Rate limit exceeded',
        statusCode: 429,
        durationMs: 310,
        requestId: 'req-ext-429'
      });

      expect(spy).toHaveBeenCalled();
      const [msg, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(msg).toContain("External API failure on provider 'virustotal'");
      expect(meta.event_type).toBe('EXTERNAL_API_FAILURE');
      expect(meta.requestId).toBe('req-ext-429');
      expect(meta.provider).toBe('virustotal');
      spy.mockRestore();
    });
  });
});
