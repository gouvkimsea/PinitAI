import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import prisma from '../src/database/client';
import { logger, sanitizeLogValue } from '../src/utils/logger';

describe('Professional Backend Logging & Monitoring Tests', () => {
  const app = createApp();

  beforeAll(async () => {
    // Ensure DB connection
    await prisma.$queryRaw`SELECT 1`;
  });

  afterAll(async () => {
    await new Promise((resolve) => setTimeout(resolve, 300));
    await prisma.$disconnect();
  });

  // =========================================================================
  // 1. Health Endpoints
  // =========================================================================
  describe('1. Health Check Endpoints', () => {
    it('GET /api/health should return overall service health and telemetry', async () => {
      const res = await request(app).get('/api/health');

      expect(res.status).toBe(200);
      expect(res.body.status).toBeDefined();
      expect(['healthy', 'degraded']).toContain(res.body.status);
      expect(res.body.timestamp).toBeDefined();
      expect(typeof res.body.uptime_seconds).toBe('number');
      expect(res.body.services).toBeDefined();
      expect(res.body.services.database).toBe('connected');
      expect(res.body.memory).toBeDefined();
      expect(res.body.version).toBeDefined();
    });

    it('GET /health (root alias) should return 200 identical to /api/health', async () => {
      const res = await request(app).get('/health');

      expect(res.status).toBe(200);
      expect(['healthy', 'degraded']).toContain(res.body.status);
      expect(res.body.services.database).toBe('connected');
    });

    it('GET /api/health/database should return database latency and connection status', async () => {
      const res = await request(app).get('/api/health/database');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body.database).toBeDefined();
      expect(res.body.database.status).toBe('connected');
      expect(typeof res.body.database.latency_ms).toBe('number');
      expect(res.body.database.latency_ms).toBeGreaterThanOrEqual(0);
      expect(res.body.database.provider).toBe('sqlite');
      expect(res.body.database.timestamp).toBeDefined();
    });

    it('GET /health/database (root alias) should return 200', async () => {
      const res = await request(app).get('/health/database');

      expect(res.status).toBe(200);
      expect(res.body.database.status).toBe('connected');
    });

    it('GET /api/health/services should report status of all core subsystems', async () => {
      const res = await request(app).get('/api/health/services');

      expect(res.status).toBe(200);
      expect(['healthy', 'degraded']).toContain(res.body.status);
      expect(res.body.services).toBeDefined();

      // Database
      expect(res.body.services.database).toBeDefined();
      expect(res.body.services.database.status).toBe('connected');
      expect(typeof res.body.services.database.latency_ms).toBe('number');

      // ClamAV
      expect(res.body.services.clamav_antivirus).toBeDefined();
      expect(['online', 'offline_fallback_active']).toContain(res.body.services.clamav_antivirus.status);

      // Task Queue
      expect(res.body.services.task_queue).toBeDefined();
      expect(res.body.services.task_queue.status).toBe('operational');
      expect(res.body.services.task_queue.mode).toBeDefined();

      // AI Explanation Engine
      expect(res.body.services.ai_explanation_engine).toBeDefined();
      expect(res.body.services.ai_explanation_engine.circuit_breaker).toBe('enabled');

      // Storage Quarantine
      expect(res.body.services.storage_quarantine).toBeDefined();
      expect(res.body.services.storage_quarantine.status).toBe('accessible');
    });

    it('GET /health/services (root alias) should return 200', async () => {
      const res = await request(app).get('/health/services');

      expect(res.status).toBe(200);
      expect(res.body.services.database.status).toBe('connected');
    });
  });

  // =========================================================================
  // 2. Sensitive Data Redaction & Privacy Guard
  // =========================================================================
  describe('2. Sensitive Data Redaction (Privacy Protection)', () => {
    it('should recursively redact passwords, tokens, API keys, and secrets', () => {
      const sensitivePayload = {
        email: 'analyst@secops.corp',
        password: 'SuperSecretPassword123!',
        password_hash: '$2a$10$abcdef1234567890',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        api_key: 'pinit_live_sec_abc1234567890',
        apiKey: 'pinit_test_xyz987654321',
        secret: 'prod_jwt_super_secret_signing_key_32c',
        authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz',
        nested: {
          client_secret: 'oauth_secret_secret',
          card_number: '4111-2222-3333-4444',
          cvv: '123',
          ssn: '000-12-3456',
          safe_field: 'public_information_ok',
        },
      };

      const sanitized = sanitizeLogValue(sensitivePayload) as Record<string, any>;

      expect(sanitized.email).toBe('analyst@secops.corp');
      expect(sanitized.password).toBe('[REDACTED]');
      expect(sanitized.password_hash).toBe('[REDACTED]');
      expect(sanitized.token).toBe('[REDACTED]');
      expect(sanitized.api_key).toBe('[REDACTED]');
      expect(sanitized.apiKey).toBe('[REDACTED]');
      expect(sanitized.secret).toBe('[REDACTED]');
      expect(sanitized.authorization).toBe('[REDACTED]');
      expect(sanitized.nested.client_secret).toBe('[REDACTED]');
      expect(sanitized.nested.card_number).toBe('[REDACTED]');
      expect(sanitized.nested.cvv).toBe('[REDACTED]');
      expect(sanitized.nested.ssn).toBe('[REDACTED]');
      expect(sanitized.nested.safe_field).toBe('public_information_ok');
    });

    it('should redact standalone Bearer token strings', () => {
      const bearerStr = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig';
      const result = sanitizeLogValue(bearerStr);
      expect(result).toBe('Bearer [REDACTED_JWT]');
    });
  });

  // =========================================================================
  // 3. Typed Structured Telemetry Methods
  // =========================================================================
  describe('3. Structured Telemetry & Event Tracking', () => {
    it('trackApiRequest should emit structured API_REQUEST event with processing time', () => {
      const spy = vi.spyOn(logger.raw, 'log');

      logger.trackApiRequest({
        method: 'POST',
        endpoint: '/api/analyze/text',
        statusCode: 200,
        durationMs: 42,
        ipHash: 'a1b2c3d4e5f6',
        userId: 'usr-12345',
        contentLength: 1024,
      });

      expect(spy).toHaveBeenCalled();
      const [level, message, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(level).toBe('info');
      expect(message).toContain('HTTP POST /api/analyze/text 200 [42ms]');
      expect(meta.event_type).toBe('API_REQUEST');
      expect(meta.durationMs).toBe(42);
      expect(meta.isSlow).toBe(false);
      expect(meta.ipHash).toBe('a1b2c3d4e5f6');

      spy.mockRestore();
    });

    it('trackApiRequest should flag slow requests (>1000ms) with warning', () => {
      const spy = vi.spyOn(logger.raw, 'log');

      logger.trackApiRequest({
        method: 'POST',
        endpoint: '/api/analyze/file',
        statusCode: 200,
        durationMs: 1450,
      });

      const [level, message, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(level).toBe('warn');
      expect(message).toContain('(SLOW_REQUEST)');
      expect(meta.isSlow).toBe(true);

      spy.mockRestore();
    });

    it('trackDetectionFailure should emit DETECTION_FAILURE event', () => {
      const spy = vi.spyOn(logger.raw, 'warn');

      logger.trackDetectionFailure({
        scanId: 'scan-uuid-1',
        detectorName: 'linguistic_detector',
        error: 'Regex engine timeout on malformed token',
        context: { length: 5000 },
      });

      expect(spy).toHaveBeenCalled();
      const [, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(meta.event_type).toBe('DETECTION_FAILURE');
      expect(meta.detectorName).toBe('linguistic_detector');
      expect(meta.scanId).toBe('scan-uuid-1');

      spy.mockRestore();
    });

    it('trackAiFailure should emit AI_FAILURE event', () => {
      const spy = vi.spyOn(logger.raw, 'warn');

      logger.trackAiFailure({
        scanId: 'scan-uuid-2',
        provider: 'Google Gemini',
        error: 'HTTP 429 Resource Exhausted',
        fallbackUsed: true,
        durationMs: 820,
      });

      expect(spy).toHaveBeenCalled();
      const [, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(meta.event_type).toBe('AI_FAILURE');
      expect(meta.provider).toBe('Google Gemini');
      expect(meta.fallbackUsed).toBe(true);

      spy.mockRestore();
    });

    it('trackFileProcessingFailure should emit FILE_PROCESSING_FAILURE event', () => {
      const spy = vi.spyOn(logger.raw, 'error');

      logger.trackFileProcessingFailure({
        scanId: 'scan-uuid-3',
        fileName: 'corrupt_archive.zip',
        stage: 'magic_bytes_inspection',
        error: 'Unexpected EOF while parsing ZIP central directory header',
        sizeBytes: 1048576,
      });

      expect(spy).toHaveBeenCalled();
      const [, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(meta.event_type).toBe('FILE_PROCESSING_FAILURE');
      expect(meta.fileName).toBe('corrupt_archive.zip');
      expect(meta.stage).toBe('magic_bytes_inspection');

      spy.mockRestore();
    });

    it('trackRateLimitViolation should emit RATE_LIMIT_VIOLATION event', () => {
      const spy = vi.spyOn(logger.raw, 'warn');

      logger.trackRateLimitViolation({
        clientKey: 'ip:192.0.2.1',
        endpoint: '/api/analyze/text',
        limit: 30,
        windowMs: 60000,
      });

      expect(spy).toHaveBeenCalled();
      const [, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(meta.event_type).toBe('RATE_LIMIT_VIOLATION');
      expect(meta.endpoint).toBe('/api/analyze/text');
      expect(meta.limit).toBe(30);

      spy.mockRestore();
    });

    it('trackAuthFailure should emit AUTH_FAILURE event with hashed IP', () => {
      const spy = vi.spyOn(logger.raw, 'warn');

      logger.trackAuthFailure({
        reason: 'Invalid or expired JWT token',
        endpoint: '/api/admin/stats',
        clientIpHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      });

      expect(spy).toHaveBeenCalled();
      const [, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(meta.event_type).toBe('AUTH_FAILURE');
      expect(meta.reason).toBe('Invalid or expired JWT token');
      expect(meta.clientIpHash).toBeDefined();

      spy.mockRestore();
    });

    it('trackSuspiciousActivity should emit SUSPICIOUS_ACTIVITY event', () => {
      const spy = vi.spyOn(logger.raw, 'error');

      logger.trackSuspiciousActivity({
        activityType: 'SSRF_ATTEMPT',
        severity: 'CRITICAL',
        details: { targetUrl: 'http://169.254.169.254/latest/meta-data/' },
        clientIpHash: '7d55d8c54734',
      });

      expect(spy).toHaveBeenCalled();
      const [, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(meta.event_type).toBe('SUSPICIOUS_ACTIVITY');
      expect(meta.activityType).toBe('SSRF_ATTEMPT');
      expect(meta.severity).toBe('CRITICAL');

      spy.mockRestore();
    });

    it('trackDatabaseError should emit DATABASE_ERROR event', () => {
      const spy = vi.spyOn(logger.raw, 'error');

      logger.trackDatabaseError({
        operation: 'scan.create',
        error: 'Timed out waiting for database transaction connection',
        durationMs: 5000,
      });

      expect(spy).toHaveBeenCalled();
      const [, meta] = spy.mock.calls[spy.mock.calls.length - 1];
      expect(meta.event_type).toBe('DATABASE_ERROR');
      expect(meta.operation).toBe('scan.create');

      spy.mockRestore();
    });
  });

  // =========================================================================
  // 4. Live Request Verification
  // =========================================================================
  describe('4. Live Request Telemetry & Error Capture', () => {
    it('should capture auth failure telemetry when accessing protected route without token', async () => {
      const spy = vi.spyOn(logger.raw, 'warn');

      const res = await request(app).get('/api/v1/auth/me');
      expect(res.status).toBe(401);

      // Verify that trackAuthFailure was called
      const authFailureCall = spy.mock.calls.find(([, meta]) => meta?.event_type === 'AUTH_FAILURE');
      expect(authFailureCall).toBeDefined();
      expect(authFailureCall?.[1]?.endpoint).toContain('/auth/me');

      spy.mockRestore();
    });

    it('should capture SSRF suspicious activity telemetry when scanning private network IP', async () => {
      const spy = vi.spyOn(logger.raw, 'error');

      const res = await request(app)
        .post('/api/analyze/url?sync=true')
        .send({ url: 'http://169.254.169.254/latest/meta-data/' });

      expect(res.status).toBe(200);
      expect(res.body.threat_level).toBe('MALICIOUS');

      // Verify suspicious activity event was tracked
      const suspiciousCall = spy.mock.calls.find(([, meta]) => meta?.event_type === 'SUSPICIOUS_ACTIVITY');
      expect(suspiciousCall).toBeDefined();
      expect(suspiciousCall?.[1]?.activityType).toBe('SSRF_ATTEMPT');

      spy.mockRestore();
    });

    it('should sanitize credentials submitted in request bodies from error logs', async () => {
      const spy = vi.spyOn(logger.raw, 'error');

      // Send malformed payload to trigger validation error
      await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'not-an-email',
          password: 'sensitive_cleartext_password_123',
        });

      // Confirm that no log argument contains the plaintext password
      for (const call of spy.mock.calls) {
        const serialized = JSON.stringify(call);
        expect(serialized).not.toContain('sensitive_cleartext_password_123');
      }

      spy.mockRestore();
    });
  });
});
