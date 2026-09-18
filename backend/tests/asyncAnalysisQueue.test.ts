import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import prisma from '../src/database/client';

describe('Asynchronous Analysis Queue & Job Architecture Tests', () => {
  const app = createApp();
  const testEmail = `async_user_${Date.now()}@example.com`;
  let authToken = '';

  beforeAll(async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: testEmail, password: 'SecureAsyncPassword123!' });
    authToken = res.body.token;
  });

  afterAll(async () => {
    await new Promise((resolve) => setTimeout(resolve, 300));
    await prisma.$disconnect();
  });

  describe('1. POST /analyze (Text Analysis Asynchronous Flow)', () => {
    it('should create an async analysis job and return job_id immediately', async () => {
      const res = await request(app)
        .post('/analyze')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          type: 'TEXT',
          content: 'Urgent notice: your crypto wallet has been locked. Verify identity now at scam-crypto.xyz',
        });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.job_id).toBeDefined();
      expect(res.body.status).toBe('QUEUED');
      expect(res.body.check_status_url).toContain(`/api/analysis/${res.body.job_id}`);

      const jobId = res.body.job_id;

      // Poll until completed (waiting for worker execution)
      let completed = false;
      for (let i = 0; i < 20; i++) {
        await new Promise((resolve) => setTimeout(resolve, 300));
        const checkRes = await request(app)
          .get(`/api/analysis/${jobId}`)
          .set('Authorization', `Bearer ${authToken}`);
        expect(checkRes.status).toBe(200);
        expect(checkRes.body.job_id).toBe(jobId);

        if (checkRes.body.status === 'COMPLETED') {
          completed = true;
          expect(checkRes.body.threat_level).toBeDefined();
          expect(checkRes.body.risk_score).toBeGreaterThan(0);
          expect(checkRes.body.summary).toBeDefined();
          expect(checkRes.body.explanation).toBeDefined();
          expect(checkRes.body.ai_explanation).toBeDefined();
          break;
        }
      }

      expect(completed).toBe(true);
    });
  });

  describe('2. POST /analyze (URL Analysis Asynchronous Flow)', () => {
    it('should create an async URL analysis job and return job_id', async () => {
      const res = await request(app)
        .post('/analyze')
        .send({
          url: 'https://paypal-security-verification.suspicious-domain.xyz/login',
        });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.job_id).toBeDefined();
      expect(res.body.type).toBe('URL');

      const jobId = res.body.job_id;

      // Check immediately via GET /api/analysis/{job_id}
      const initialCheck = await request(app).get(`/api/analysis/${jobId}`);
      expect(initialCheck.status).toBe(200);
      expect(initialCheck.body.job_id).toBe(jobId);
      expect(['QUEUED', 'PROCESSING', 'COMPLETED']).toContain(initialCheck.body.status);
    });
  });

  describe('3. POST /analyze (File Analysis Asynchronous Flow)', () => {
    it('should accept uploaded file asynchronously and return job_id', async () => {
      const fileBuffer = Buffer.from('MZ\x90\x00\x03\x00\x00\x00BinaryPayloadTest');

      const res = await request(app)
        .post('/analyze')
        .attach('file', fileBuffer, 'suspicious_installer.exe');

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.job_id).toBeDefined();
      expect(res.body.type).toBe('FILE');

      const jobId = res.body.job_id;

      // Poll until worker finishes processing file
      let completed = false;
      for (let i = 0; i < 20; i++) {
        await new Promise((resolve) => setTimeout(resolve, 300));
        const checkRes = await request(app).get(`/api/analysis/${jobId}`);
        expect(checkRes.status).toBe(200);
        expect(checkRes.body.job_id).toBe(jobId);

        if (checkRes.body.status === 'COMPLETED') {
          completed = true;
          expect(checkRes.body.file_type).toBeDefined();
          expect(checkRes.body.detected_indicators).toBeDefined();
          break;
        }
      }

      expect(completed).toBe(true);
    }, 15000);
  });

  describe('4. POST /api/analyze/text?async=true', () => {
    it('should queue large or async text analyses when requested', async () => {
      const res = await request(app)
        .post('/api/analyze/text?async=true')
        .send({
          content: 'Bank notice: Click to verify your debit card to prevent immediate suspension.',
        });

      expect(res.status).toBe(202);
      expect(res.body.job_id).toBeDefined();
      expect(res.body.status).toBe('QUEUED');
      expect(res.body.check_status_url).toContain(`/api/analysis/${res.body.job_id}`);
    });

    it('should automatically queue large text (> 1000 characters) asynchronously without blocking', async () => {
      const largeContent = 'Important alert: Please update your bank credentials immediately. '.repeat(20);
      expect(largeContent.length).toBeGreaterThan(1000);

      const res = await request(app)
        .post('/api/analyze/text')
        .send({ content: largeContent });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.job_id).toBeDefined();
      expect(res.body.status).toBe('QUEUED');
      expect(res.body.message).toContain('Large text analysis job created');
      expect(res.body.check_status_url).toContain(`/api/analysis/${res.body.job_id}`);
    });
  });

  describe('5. Asynchronous AI Explanation Jobs', () => {
    it('should queue AI explanation job asynchronously via POST /analyze (type: AI)', async () => {
      const res = await request(app)
        .post('/analyze')
        .send({
          type: 'AI',
          content: 'Verify your cryptocurrency wallet seed phrase now',
          risk_score: 85,
          indicators: ['Seed phrase solicitation', 'High urgency'],
        });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.job_id).toBeDefined();
      expect(res.body.type).toBe('AI');
      expect(res.body.status).toBe('QUEUED');
      expect(res.body.check_status_url).toContain(`/api/analysis/${res.body.job_id}`);

      const jobId = res.body.job_id;

      // Poll until worker finishes AI job
      let completed = false;
      for (let i = 0; i < 20; i++) {
        await new Promise((resolve) => setTimeout(resolve, 300));
        const checkRes = await request(app).get(`/api/analysis/${jobId}`);
        if (checkRes.body.status === 'COMPLETED') {
          completed = true;
          expect(checkRes.body.summary).toBeDefined();
          expect(checkRes.body.explanation).toBeDefined();
          break;
        }
      }
      expect(completed).toBe(true);
    });

    it('should queue AI explanation job asynchronously via POST /api/analyze/explain?async=true', async () => {
      const res = await request(app)
        .post('/api/analyze/explain?async=true')
        .send({
          content: 'Urgent package delivery pending fee',
          threat_category: 'delivery_scam',
          risk_score: 75,
          indicators: ['Fake delivery tracking'],
        });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.job_id).toBeDefined();
      expect(res.body.type).toBe('AI');
      expect(res.body.status).toBe('QUEUED');
    });
  });

  describe('6. Status Checking and Polling (GET /api/analysis/{job_id})', () => {
    it('should return 404 for nonexistent job IDs', async () => {
      const res = await request(app).get('/api/analysis/nonexistent-job-uuid-12345');
      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('SCAN_NOT_FOUND');
    });

    it('should also be accessible via root alias GET /analysis/{job_id}', async () => {
      const createRes = await request(app)
        .post('/analyze')
        .send({ content: 'Free coupon claim' });

      const jobId = createRes.body.job_id;
      const getRes = await request(app).get(`/analysis/${jobId}`);
      expect(getRes.status).toBe(200);
      expect(getRes.body.job_id).toBe(jobId);
    });

    it('should support root alias POST /analysis as drop-in replacement for POST /analyze', async () => {
      const createRes = await request(app)
        .post('/analysis')
        .send({
          url: 'https://security-verify-suspicious.com/auth',
        });

      expect(createRes.status).toBe(202);
      expect(createRes.body.success).toBe(true);
      expect(createRes.body.job_id).toBeDefined();
      expect(createRes.body.type).toBe('URL');
    });
  });
});
