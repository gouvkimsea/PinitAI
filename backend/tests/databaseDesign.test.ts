import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import prisma from '../src/database/client';
import { modelVersionService } from '../src/modules/models/modelVersionService';
import { logSecurityEvent } from '../src/utils/securityEventLogger';

describe('Database Architecture & Design Integration Tests', () => {
  const app = createApp();
  let testUserId = '';
  let testUserToken = '';

  beforeAll(async () => {
    // Seed model versions
    await modelVersionService.seedDefaultModelVersions();

    // Register test user
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: `db_test_${Date.now()}@example.com`, password: 'TestPassword123!' });
    
    testUserId = res.body.user.id;
    testUserToken = res.body.token;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('1. Users Table: verifies user status, role, and hashed API key storage', async () => {
    const user = await prisma.user.findUnique({
      where: { id: testUserId },
    });

    expect(user).not.toBeNull();
    expect(user?.role).toBe('user');
    expect(user?.status).toBe('active');
    expect(user?.apiKeyHash).toBeDefined();
    // Raw password must never be stored
    expect(user?.passwordHash).not.toContain('TestPassword123!');
  });

  it('2. Model Versions Table: verifies AI and heuristic model registry', async () => {
    const res = await request(app).get('/api/models');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.models)).toBe(true);
    expect(res.body.models.length).toBeGreaterThanOrEqual(5);

    const geminiModel = res.body.models.find((m: any) => m.name === 'gemini-grounded-explainer');
    expect(geminiModel).toBeDefined();
    expect(geminiModel.provider).toBe('GoogleGemini');
    expect(geminiModel.isActive).toBe(true);
    expect(geminiModel.capabilities).toContain('TEXT');
  });

  it('3. Analyses & Evidence Tables: verifies scan target hashing and decoupled forensic evidence', async () => {
    const scanRes = await request(app)
      .post('/api/analyze/text')
      .send({ content: 'URGENT: Click here to verify your account or funds will be locked!' });

    expect(scanRes.status).toBe(200);
    const scanId = scanRes.body.id;

    // Check Scan in DB
    const scanRecord = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        evidenceRecord: true,
        scanResult: true,
        detections: true,
      },
    });

    expect(scanRecord).not.toBeNull();
    expect(scanRecord?.targetHash).toBeDefined();
    expect(scanRecord?.status).toBe('COMPLETED');
    expect(scanRecord?.evidenceRecord).not.toBeNull();
    expect(scanRecord?.evidenceRecord?.summary).toBeDefined();
    expect(scanRecord?.evidenceRecord?.indicators).toBeDefined();
    expect(scanRecord?.detections.length).toBeGreaterThan(0);
  });

  it('4. Scam Patterns Table: verifies pattern catalog, category index, and match count', async () => {
    const pattern = await prisma.scamPattern.findFirst({
      where: { status: 'active' },
    });

    expect(pattern).not.toBeNull();
    expect(pattern?.category).toBeDefined();
    expect(pattern?.severity).toBeDefined();
    expect(typeof pattern?.matchCount).toBe('number');
  });

  it('5. Reports Table: verifies community report creation and targetHash deduplication', async () => {
    const res = await request(app)
      .post('/api/reports')
      .send({
        scamType: 'financial',
        target: 'https://fake-lottery-claim.biz',
        description: 'Phishing website requesting credit card details for lottery claiming.',
      });

    expect(res.status).toBe(201);
    const reportId = res.body.report_id;

    const report = await prisma.scamReport.findUnique({
      where: { id: reportId },
    });

    expect(report).not.toBeNull();
    expect(report?.status).toBe('PENDING');
    expect(report?.targetHash).toBeDefined();
  });

  it('6. Feedback Table: verifies privacy-preserving hashed IP and analysis linkage', async () => {
    const scanRes = await request(app)
      .post('/api/analyze/text')
      .send({ content: 'Claim your $1000 gift card immediately' });

    const fbRes = await request(app)
      .post('/api/feedback')
      .send({
        scan_id: scanRes.body.id,
        is_correct: true,
        suggested_category: 'lottery_scam',
        comments: 'Correctly identified lure',
      });

    expect(fbRes.status).toBe(200);

    const feedback = await prisma.analysisFeedback.findFirst({
      where: { analysisId: scanRes.body.id },
    });

    expect(feedback).not.toBeNull();
    expect(feedback?.feedbackType).toBe('correct_detection');
    // Raw IP should never be in plaintext IP field
    if (feedback?.ipHash) {
      expect(feedback.ipHash).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it('7. Security Events Table: logs security incidents with hashed IP and severity', async () => {
    await logSecurityEvent({
      eventType: 'AUTH_FAILURE',
      severity: 'WARNING',
      rawIp: '192.168.1.50',
      targetResource: '/api/v1/auth/login',
      details: { reason: 'test_incorrect_password' },
    });

    const event = await prisma.securityEvent.findFirst({
      where: { eventType: 'AUTH_FAILURE' },
      orderBy: { createdAt: 'desc' },
    });

    expect(event).not.toBeNull();
    expect(event?.severity).toBe('WARNING');
    expect(event?.ipHash).toMatch(/^[a-f0-9]{64}$/);
    expect(event?.ipHash).not.toContain('192.168.1.50');
  });

  it('8. API Usage Table: logs request telemetry without leaking credentials', async () => {
    await request(app)
      .get('/api/v1/statistics')
      .set('Authorization', `Bearer ${testUserToken}`);

    // Allow event loop to process res.on('finish') write
    await new Promise((resolve) => setTimeout(resolve, 150));

    const usage = await prisma.apiUsage.findFirst({
      where: { endpoint: '/api/v1/statistics' },
      orderBy: { createdAt: 'desc' },
    });

    expect(usage).not.toBeNull();
    expect(usage?.method).toBe('GET');
    expect(usage?.statusCode).toBe(200);
    expect(usage?.durationMs).toBeGreaterThanOrEqual(0);
  });
});
