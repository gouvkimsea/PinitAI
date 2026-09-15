import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { createApp } from '../src/app';
import prisma from '../src/database/client';

describe('Standardized API Responses Contract Tests', () => {
  const app = createApp();
  const testDir = path.resolve(__dirname, './temp_standardized_test');
  let authToken = '';

  beforeAll(async () => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }

    // Register a test user
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        email: `std_resp_${Date.now()}@example.com`,
        password: 'StrongPassword123!',
      });
    authToken = res.body.token;
  });

  afterAll(async () => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
    await prisma.$disconnect();
  });

  const EXPECTED_SUCCESS_KEYS = [
    'success',
    'analysis_id',
    'risk_score',
    'classification',
    'confidence',
    'evidence',
    'detectors',
    'recommendation',
    'created_at',
    'model_version',
  ];

  function assertStandardSuccessfulAnalysis(body: any): void {
    for (const key of EXPECTED_SUCCESS_KEYS) {
      expect(body, `Missing required key: ${key}`).toHaveProperty(key);
    }
    expect(body.success).toBe(true);
    expect(typeof body.analysis_id).toBe('string');
    expect(body.analysis_id.length).toBeGreaterThan(0);
    expect(typeof body.risk_score).toBe('number');
    expect(body.risk_score).toBeGreaterThanOrEqual(0);
    expect(body.risk_score).toBeLessThanOrEqual(100);
    expect(typeof body.classification).toBe('string');
    expect(body.classification.length).toBeGreaterThan(0);
    expect(body.confidence).toBeDefined();
    expect(typeof body.evidence).toBe('object');
    expect(body.evidence).not.toBeNull();
    expect(Array.isArray(body.evidence.indicators)).toBe(true);
    expect(Array.isArray(body.detectors)).toBe(true);
    expect(typeof body.recommendation).toBe('string');
    expect(body.recommendation.length).toBeGreaterThan(0);
    expect(typeof body.created_at).toBe('string');
    expect(isNaN(Date.parse(body.created_at))).toBe(false);
    expect(typeof body.model_version).toBe('string');
    expect(body.model_version.length).toBeGreaterThan(0);

    // Security: ensure no sensitive internal leaks
    expect(body.stack).toBeUndefined();
    expect(body.internal_path).toBeUndefined();
  }

  function assertStandardError(body: any, expectedCode?: string): void {
    expect(body.success).toBe(false);
    expect(typeof body.error_code).toBe('string');
    expect(body.error_code.length).toBeGreaterThan(0);
    if (expectedCode) {
      expect(body.error_code).toBe(expectedCode);
    }
    expect(typeof body.message).toBe('string');
    expect(body.message.length).toBeGreaterThan(0);
    expect(typeof body.request_id).toBe('string');
    expect(body.request_id.length).toBeGreaterThan(0);

    // Backward compatibility: error object with code and message
    expect(body.error).toBeDefined();
    expect(body.error.code).toBe(body.error_code);
    expect(body.error.message).toBe(body.message);

    // Critical Security Requirement: No stack traces or path leaks
    expect(body.stack).toBeUndefined();
    expect(body.error?.stack).toBeUndefined();
    expect(JSON.stringify(body)).not.toMatch(/[a-zA-Z]:\\[\w.-]+/); // No Windows paths
  }

  describe('Successful Analysis Schema Standardization', () => {
    it('POST /api/analyze/text returns all 10 mandatory standardized analysis fields', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'URGENT: Click http://secure-login-account-verify.com to avoid suspension of your account.',
        });

      expect(res.status).toBe(200);
      assertStandardSuccessfulAnalysis(res.body);
      expect(res.headers['x-request-id']).toBeDefined();
    });

    it('POST /api/analyze/url?sync=true returns all 10 mandatory standardized analysis fields', async () => {
      const res = await request(app)
        .post('/api/analyze/url?sync=true')
        .send({
          url: 'https://paypal-security-alert-login.com',
        });

      expect(res.status).toBe(200);
      assertStandardSuccessfulAnalysis(res.body);
      expect(res.headers['x-request-id']).toBeDefined();
    });

    it('POST /api/analyze/file?sync=true returns all 10 mandatory standardized analysis fields', async () => {
      const filePath = path.join(testDir, 'standard_test_file.txt');
      await fs.promises.writeFile(filePath, 'Account verification request statement.');

      const res = await request(app)
        .post('/api/analyze/file?sync=true')
        .attach('file', filePath);

      expect(res.status).toBe(200);
      assertStandardSuccessfulAnalysis(res.body);
      expect(res.headers['x-request-id']).toBeDefined();
    });

    it('GET /api/analysis/:id returns all 10 mandatory standardized fields on completed record', async () => {
      // First submit text analysis to get a persistent scan record
      const initial = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'Congratulations! You won $10,000 lottery. Send $200 processing fee.',
        });

      expect(initial.status).toBe(200);
      const scanId = initial.body.analysis_id;
      expect(scanId).toBeDefined();

      // Retrieve via GET /api/analysis/:id
      const res = await request(app).get(`/api/analysis/${scanId}`);
      expect(res.status).toBe(200);
      assertStandardSuccessfulAnalysis(res.body);
      expect(res.body.analysis_id).toBe(scanId);
    });

    it('GET /api/v1/files/scan/:id returns all 10 mandatory standardized fields on completed file', async () => {
      const filePath = path.join(testDir, 'v1_file_test.txt');
      await fs.promises.writeFile(filePath, 'Sample text content for v1 scan.');

      const uploadRes = await request(app)
        .post('/api/v1/files/scan')
        .set('Authorization', `Bearer ${authToken}`)
        .attach('file', filePath);

      expect(uploadRes.status).toBe(202);
      const scanId = uploadRes.body.scan_id;

      // Allow background worker to complete
      await new Promise((r) => setTimeout(r, 600));

      const res = await request(app).get(`/api/v1/files/scan/${scanId}`);
      expect(res.status).toBe(200);
      if (res.body.status === 'COMPLETED') {
        assertStandardSuccessfulAnalysis(res.body);
      }
    });

    it('GET /api/v1/urls/scan/:id returns all 10 mandatory standardized fields on completed URL', async () => {
      const submitRes = await request(app)
        .post('/api/v1/urls/scan')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ url: 'https://example-standardized-check.org' });

      expect(submitRes.status).toBe(202);
      const scanId = submitRes.body.scan_id;

      // Allow worker execution
      await new Promise((r) => setTimeout(r, 600));

      const res = await request(app).get(`/api/v1/urls/scan/${scanId}`);
      expect(res.status).toBe(200);
      if (res.body.status === 'COMPLETED') {
        assertStandardSuccessfulAnalysis(res.body);
      }
    });
  });

  describe('Error Response Schema Standardization', () => {
    it('Validation Error (400) adheres strictly to standardized error contract', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({ content: '' }); // Invalid: empty content

      expect(res.status).toBe(400);
      assertStandardError(res.body, 'VALIDATION_ERROR');
      expect(res.headers['x-request-id']).toBeDefined();
    });

    it('Authentication Error (401) adheres strictly to standardized error contract', async () => {
      const res = await request(app)
        .get('/api/admin/stats'); // Protected admin route

      expect(res.status).toBe(401);
      assertStandardError(res.body, 'UNAUTHORIZED');
    });

    it('Forbidden Role Error (403) adheres strictly to standardized error contract', async () => {
      const res = await request(app)
        .get('/api/admin/stats')
        .set('Authorization', `Bearer ${authToken}`); // Regular user token, not admin

      expect(res.status).toBe(403);
      assertStandardError(res.body, 'FORBIDDEN');
    });

    it('Not Found Error (404) adheres strictly to standardized error contract', async () => {
      const res = await request(app)
        .get('/api/analysis/00000000-0000-0000-0000-000000000000');

      expect(res.status).toBe(404);
      assertStandardError(res.body, 'SCAN_NOT_FOUND');
    });

    it('File Required Error (400) adheres strictly to standardized error contract', async () => {
      const res = await request(app)
        .post('/api/analyze/file'); // No multipart file attached

      expect(res.status).toBe(400);
      assertStandardError(res.body, 'FILE_REQUIRED');
    });

    it('Payload Too Large Error (413) adheres strictly to standardized error contract', async () => {
      const hugeContent = 'A'.repeat(60000); // Exceeds maxTextLengthChars (50,000)

      const res = await request(app)
        .post('/api/analyze/text')
        .send({ content: hugeContent });

      expect(res.status).toBe(413);
      assertStandardError(res.body, 'PAYLOAD_TOO_LARGE');
    });

    it('Zero stack trace or internal path leakage on unhandled errors', async () => {
      // Send malformed JSON or trigger error handler directly
      const res = await request(app)
        .post('/api/feedback')
        .send({ scan_id: 'invalid-scan-id-xyz', is_correct: 'not-a-boolean' });

      expect(res.status).toBe(400);
      assertStandardError(res.body, 'VALIDATION_ERROR');

      const bodyStr = JSON.stringify(res.body);
      expect(bodyStr).not.toContain('node_modules');
      expect(bodyStr).not.toContain('src/');
      expect(bodyStr).not.toContain('at ');
      expect(res.body.stack).toBeUndefined();
    });
  });

  describe('Backward Compatibility Preservation', () => {
    it('Preserves legacy aliases id, scan_id, status, threat_level, summary alongside standardized keys', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'Urgent: please wire $500 to this account for your tax refund.',
        });

      expect(res.status).toBe(200);

      // Standard keys
      expect(res.body.success).toBe(true);
      expect(res.body.analysis_id).toBeDefined();
      expect(res.body.risk_score).toBeDefined();
      expect(res.body.model_version).toBe('2.1.0');

      // Legacy aliases for existing UI and tests
      expect(res.body.id).toBe(res.body.analysis_id);
      expect(res.body.scan_id).toBe(res.body.analysis_id);
      expect(res.body.status).toBe('COMPLETED');
      expect(res.body.threat_level).toBeDefined();
      expect(res.body.summary).toBeDefined();
      expect(Array.isArray(res.body.signals)).toBe(true);
      expect(Array.isArray(res.body.recommended_actions)).toBe(true);
    });
  });
});
