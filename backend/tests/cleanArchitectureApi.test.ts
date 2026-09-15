import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { createApp } from '../src/app';
import prisma from '../src/database/client';

describe('Clean Canonical Scam Detection Architecture API Tests', () => {
  const app = createApp();
  const testDir = path.resolve(__dirname, './temp_clean_api_test');
  let _authToken = '';

  beforeAll(async () => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }

    // Register user for authenticated requests if needed
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: `clean_arch_${Date.now()}@example.com`, password: 'StrongPassword123!' });
    _authToken = res.body.token;
  });

  afterAll(async () => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
    await prisma.$disconnect();
  });

  it('GET /api/health should return system status (Clean Endpoint)', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
    expect(res.body.services.database).toBe('connected');
  });

  it('POST /api/analyze/text should run full pipeline for English scam message', async () => {
    const res = await request(app)
      .post('/api/analyze/text')
      .send({
        content: 'URGENT: Your bank account has been suspended! Send your OTP password and wire $500 now.',
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.id).toBeDefined();
    expect(res.body.mode).toBe('text');
    expect(res.body.risk_score).toBeGreaterThan(40);
    expect(['suspicious', 'high_risk', 'malicious']).toContain(res.body.risk_level);
    expect(res.body.summary).toBeDefined();
    expect(res.body.ai_explanation).toBeDefined();
    expect(res.body.signals.length).toBeGreaterThan(0);
    expect(res.body.recommended_actions.length).toBeGreaterThan(0);

    // Verify record in Database Layer
    const saved = await prisma.scan.findUnique({
      where: { id: res.body.id },
      include: { scanResult: true, detections: true },
    });
    expect(saved).not.toBeNull();
    expect(saved?.type).toBe('MESSAGE');
    expect(saved?.scanResult?.summary).toBeDefined();
  });

  it('POST /api/analyze/text should run full pipeline for Khmer (ភាសាខ្មែរ) scam message', async () => {
    const res = await request(app)
      .post('/api/analyze/text')
      .send({
        content: 'សូមអបអរសាទរ! អ្នកបានឈ្នះរង្វាន់ធំ $5,000 សូមផ្ញើលេខកូដសម្ងាត់ OTP និងលេខទូរស័ព្ទជាបន្ទាន់។',
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.id).toBeDefined();
    expect(['km', 'km-en']).toContain(res.body.technical_evidence.language_detected);
    expect(res.body.risk_score).toBeGreaterThan(40);
    expect(res.body.summary).toContain('ការ');
    expect(res.body.recommended_actions.length).toBeGreaterThan(0);
  });

  it('POST /api/analyze/text should reject invalid empty input (Validation Layer)', async () => {
    const res = await request(app)
      .post('/api/analyze/text')
      .send({ content: '   ' });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it('POST /api/analyze/url should accept and queue URL for scanning (Clean Endpoint)', async () => {
    const res = await request(app)
      .post('/api/analyze/url')
      .send({ url: 'https://paypal-verify-security-login.xyz' });

    expect(res.status).toBe(202);
    expect(res.body.success).toBe(true);
    expect(res.body.id).toBeDefined();
    expect(res.body.status).toBe('QUEUED');
    expect(res.body.check_status_url).toBe(`/api/analysis/${res.body.id}`);

    // Allow worker execution
    await new Promise((resolve) => setTimeout(resolve, 600));

    // Retrieve via clean GET /api/analysis/{id}
    const pollRes = await request(app).get(`/api/analysis/${res.body.id}`);
    expect(pollRes.status).toBe(200);
    expect(pollRes.body.success).toBe(true);
    expect(pollRes.body.id).toBe(res.body.id);
  });

  it('POST /api/analyze/url?sync=true should execute synchronous URL analysis', async () => {
    const res = await request(app)
      .post('/api/analyze/url?sync=true')
      .send({ url: 'https://example-clean-site.org' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.id).toBeDefined();
    expect(res.body.status).toBe('COMPLETED');
    expect(res.body.summary).toBeDefined();
  });

  it('POST /api/analyze/file should accept and queue uploaded file (Clean Endpoint)', async () => {
    const filePath = path.join(testDir, 'clean_architecture_doc.txt');
    await fs.promises.writeFile(filePath, 'Clean Architecture Verification Sample');

    const res = await request(app)
      .post('/api/analyze/file')
      .attach('file', filePath);

    expect(res.status).toBe(202);
    expect(res.body.success).toBe(true);
    expect(res.body.id).toBeDefined();
    expect(res.body.status).toBe('QUEUED');

    // Allow worker execution
    await new Promise((resolve) => setTimeout(resolve, 600));

    // Retrieve via clean GET /api/analysis/{id}
    const analysisRes = await request(app).get(`/api/analysis/${res.body.id}`);
    expect(analysisRes.status).toBe(200);
    expect(analysisRes.body.success).toBe(true);
    expect(analysisRes.body.id).toBe(res.body.id);
    expect(analysisRes.body.type).toBe('FILE');
  });

  it('POST /api/reports should accept community report (Clean Endpoint)', async () => {
    const res = await request(app)
      .post('/api/reports')
      .send({
        scamType: 'phishing',
        target: 'https://suspicious-telegram-bot.top',
        description: 'Telegram bot claiming to double crypto deposits within 24 hours.',
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.report_id).toBeDefined();
  });

  it('POST /api/feedback should record accuracy feedback (Clean Endpoint & Feedback System)', async () => {
    // Submit text first to get a scan ID
    const scanRes = await request(app)
      .post('/api/analyze/text')
      .send({ content: 'Free crypto giveaway click link' });

    const scanId = scanRes.body.id;

    // Send feedback
    const res = await request(app)
      .post('/api/feedback')
      .send({
        scan_id: scanId,
        is_correct: true,
        suggested_category: 'CRYPTO_SCAM',
        comments: 'Accurately detected crypto giveaway scam',
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('GET /api/analysis/{id} should return 404 for nonexistent scan', async () => {
    const res = await request(app).get('/api/analysis/nonexistent-id-99999');
    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('SCAN_NOT_FOUND');
  });
});
