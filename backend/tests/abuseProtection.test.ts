import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import prisma from '../src/database/client';
import { config } from '../src/config';

describe('Comprehensive Abuse Protection & Rate Limiting Integration Tests', () => {
  const app = createApp();
  const testEmail = `abuse_test_${Date.now()}@example.com`;
  let authToken = '';

  beforeAll(async () => {
    // Register user for authenticated requests
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: testEmail, password: 'SecureAbusePassword123!' });
    authToken = res.body.token;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  describe('1. Request Payload Size Protection (Text & Body)', () => {
    it('should reject text analysis payloads exceeding max character limits', async () => {
      const oversizedText = 'A'.repeat(config.payloadLimits.maxTextLengthChars + 500);

      const res = await request(app)
        .post('/api/analyze/text')
        .send({ content: oversizedText });

      expect([400, 413]).toContain(res.status);
      expect(res.body.success).toBe(false);
      expect(res.body.error).toBeDefined();
    });

    it('should allow normal text content within acceptable limits', async () => {
      const normalText = 'Congratulations! You won a gift card. Claim it now at claim-prize.com';

      const res = await request(app)
        .post('/api/analyze/text')
        .send({ content: normalText });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe('2. URL Analysis Abuse Protection', () => {
    it('should enforce URL length boundaries', async () => {
      const hugeUrl = `https://example.com/${'long-path/'.repeat(500)}`;

      const res = await request(app)
        .post('/api/analyze/url')
        .send({ url: hugeUrl });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  describe('3. File Analysis Abuse Protection', () => {
    it('should reject 0-byte files to prevent empty payload DOS', async () => {
      const res = await request(app)
        .post('/api/analyze/file')
        .attach('file', Buffer.alloc(0), 'empty.bin');

      expect([400, 422]).toContain(res.status);
      expect(res.body.success).toBe(false);
    });
  });

  describe('4. AI Request Abuse Protection', () => {
    it('should accept valid explanation requests within limits', async () => {
      const res = await request(app)
        .post('/api/analyze/explain')
        .send({
          content: 'Urgent: Wire money to this account immediately',
          target_type: 'TEXT',
          threat_category: 'URGENCY_SCAM',
          risk_score: 75,
          indicators: ['High urgency tone', 'Direct wire demand'],
        });

      expect([200, 429]).toContain(res.status);
    });
  });

  describe('5. Community Reports Abuse Protection', () => {
    it('should reject invalid or excessively short report descriptions', async () => {
      const res = await request(app)
        .post('/api/reports')
        .send({
          scamType: 'phishing',
          description: 'bad', // less than 5 characters
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should accept well-formed community scam reports', async () => {
      const res = await request(app)
        .post('/api/reports')
        .send({
          scamType: 'investment_fraud',
          target: 'https://fake-crypto-returns.xyz',
          description: 'This platform claims 200% daily returns on crypto staking.',
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
    });
  });

  describe('6. Security Event Logging on Abuse', () => {
    it('should record security events in the database when payload abuse occurs', async () => {
      // Trigger oversized payload check
      const oversizedText = 'B'.repeat(config.payloadLimits.maxTextLengthChars + 200);

      await request(app)
        .post('/api/analyze/text')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ content: oversizedText });

      // Check if security event was recorded
      const event = await prisma.securityEvent.findFirst({
        where: { eventType: 'PAYLOAD_TOO_LARGE' },
        orderBy: { createdAt: 'desc' },
      });

      expect(event).toBeDefined();
      expect(event?.severity).toBe('WARNING');
      expect(event?.targetResource).toContain('/api/analyze/text');
    });
  });
});
