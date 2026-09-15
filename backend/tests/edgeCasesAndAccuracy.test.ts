import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app';
import { config } from '../src/config';
import prisma from '../src/database/client';
import { detectionPipeline } from '../src/pipeline/orchestrator';
import { secureFileAnalyzer } from '../src/modules/file';
import { textNormalizer } from '../src/pipeline/normalization';

describe('Complete Backend Edge Cases & Accuracy Benchmark Suite', () => {
  const app = createApp();
  const testDir = path.resolve(__dirname, './temp_edge_cases_test');
  let _authToken = '';

  beforeAll(async () => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }

    const regRes = await request(app)
      .post('/api/auth/register')
      .send({
        email: `edge_tester_${Date.now()}@example.com`,
        password: 'StrongPassword123!',
      });
    _authToken = regRes.body.token;
  });

  afterAll(async () => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
    await prisma.$disconnect();
  });

  // =========================================================================
  // 1. Clearly Safe Content Tests
  // =========================================================================
  describe('1. Clearly Safe Content Scenarios', () => {
    it('should classify conversational non-scam messages as Low Risk (SAFE)', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'Hey Sarah, are we still meeting for lunch at the cafeteria tomorrow at 12:30pm?',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.risk_score).toBeLessThan(25);
      expect(res.body.threat_level).toBe('SAFE');
      expect(['Low Risk', 'Mild Risk']).toContain(res.body.classification);
      expect(res.body.recommendation).toBeDefined();
    });

    it('should classify internal engineering/technical communications as Low Risk', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'The pull request #402 has been merged into main. Unit tests are all green on CI.',
        });

      expect(res.status).toBe(200);
      expect(res.body.risk_score).toBeLessThan(20);
      expect(res.body.threat_level).toBe('SAFE');
    });

    it('should evaluate legitimate high-reputation domains as SAFE with 0 risk score', async () => {
      const res = await request(app)
        .post('/api/analyze/url?sync=true')
        .send({ url: 'https://en.wikipedia.org/wiki/Computer_security' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.risk_score).toBeLessThan(20);
      expect(res.body.threat_level).toBe('SAFE');
    });

    it('should analyze benign plain text files as clean and safe', async () => {
      const filePath = path.join(testDir, 'clean_notes.txt');
      await fs.promises.writeFile(filePath, 'Meeting notes from quarterly planning session.');

      const res = await request(app)
        .post('/api/analyze/file?sync=true')
        .attach('file', filePath);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.risk_score).toBeLessThan(20);
      expect(res.body.threat_level).toBe('SAFE');
    });
  });

  // =========================================================================
  // 2. Clearly Malicious Content Tests
  // =========================================================================
  describe('2. Clearly Malicious Content Scenarios', () => {
    it('should detect urgent banking credential harvest scam with High/Critical risk', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'CRITICAL ALERT: Your Chase account has been locked due to suspicious activity. Send your OTP code and card details now to avoid permanent closure.',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.risk_score).toBeGreaterThanOrEqual(60);
      expect(['Critical Risk', 'High Risk', 'Suspicious']).toContain(res.body.classification);
      expect(['MALICIOUS', 'HIGH_RISK', 'SUSPICIOUS']).toContain(res.body.threat_level);
      expect(res.body.evidence.indicators.length).toBeGreaterThan(0);
    });

    it('should detect classic lottery / advance-fee 419 scam with high risk', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'CONGRATULATIONS! You have won $1,000,000 in the International Mega Lottery. Wire $250 processing fee via Western Union or crypto to claim your jackpot immediately!',
        });

      expect(res.status).toBe(200);
      expect(res.body.risk_score).toBeGreaterThan(50);
      expect(res.body.evidence.indicators.length).toBeGreaterThan(0);
    });

    it('should flag obvious phishing and malicious domain patterns', async () => {
      const res = await request(app)
        .post('/api/analyze/url?sync=true')
        .send({ url: 'https://paypal-security-account-verification-login.com' });

      expect(res.status).toBe(200);
      expect(res.body.risk_score).toBeGreaterThanOrEqual(60);
      expect(['MALICIOUS', 'HIGH_RISK']).toContain(res.body.threat_level);
    });

    it('should detect EICAR antivirus test file as critical malware', async () => {
      const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
      const filePath = path.join(testDir, 'eicar_test.com');
      await fs.promises.writeFile(filePath, eicarString);

      const res = await request(app)
        .post('/api/analyze/file?sync=true')
        .attach('file', filePath);

      expect(res.status).toBe(200);
      expect(res.body.risk_score).toBeGreaterThanOrEqual(80);
      expect(res.body.classification).toBe('Critical Risk');
      expect(res.body.threat_level).toBe('MALICIOUS');
    });
  });

  // =========================================================================
  // 3. Ambiguous Content Tests (Borderline & Uncertainty Handling)
  // =========================================================================
  describe('3. Ambiguous Content & Borderline Scenarios', () => {
    it('should handle mildly urgent operational reminders without panic classification', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'Friendly reminder: Please remember to submit your weekly timesheet before 5:00 PM today.',
        });

      expect(res.status).toBe(200);
      // Mild urgency exists, but NO credential requests or banking lures
      expect(res.body.risk_score).toBeLessThan(45);
      expect(res.body.threat_level).not.toBe('MALICIOUS');
    });

    it('should evaluate commercial marketing newsletter with appropriate nuance', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'Limited time flash sale! Get 30% discount on all outdoor gear this weekend only. Visit our official retail store.',
        });

      expect(res.status).toBe(200);
      expect(res.body.risk_score).toBeLessThan(45);
      expect(res.body.threat_level).not.toBe('MALICIOUS');
    });
  });

  // =========================================================================
  // 4. False Positive Resistance Tests
  // =========================================================================
  describe('4. False Positive Resistance Scenarios', () => {
    it('should NOT flag legitimate password reset confirmations as scam', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'You requested a password reset for your account. If you did not make this request, you can safely disregard this message.',
        });

      expect(res.status).toBe(200);
      expect(res.body.threat_level).not.toBe('MALICIOUS');
      expect(res.body.risk_score).toBeLessThanOrEqual(55);
    });

    it('should NOT flag official invoice delivery as malicious scam', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'Attached is Invoice #9021 for the cloud hosting services rendered during August 2026. Paid via auto-billing.',
        });

      expect(res.status).toBe(200);
      expect(res.body.risk_score).toBeLessThan(40);
      expect(res.body.threat_level).toBe('SAFE');
    });

    it('should NOT flag open-source software release announcements containing words like "free" or "update"', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({
          content: 'The free and open-source Linux kernel 6.12 update is now available for download from kernel.org.',
        });

      expect(res.status).toBe(200);
      expect(res.body.risk_score).toBeLessThan(30);
      expect(res.body.threat_level).toBe('SAFE');
    });
  });

  // =========================================================================
  // 5. False Negative Evasion Resistance Tests
  // =========================================================================
  describe('5. False Negative Evasion Resistance Scenarios', () => {
    it('should catch leetspeak-obfuscated credential harvest lure', async () => {
      const rawText = 'URG3NT: Cl!ck h3r3 t0 v3r!fy y0ur b@nk @cc0unt p@ssw0rd immediately';
      const normalized = textNormalizer.normalize(rawText);

      // Normalizer should deobfuscate leetspeak characters
      expect(normalized.deobfuscatedText).toContain('verify');
      expect(normalized.deobfuscatedText).toContain('bank');
      expect(normalized.deobfuscatedText).toContain('account');

      const result = await detectionPipeline.execute({
        type: 'TEXT',
        rawContent: rawText,
      });

      expect(result.risk_score).toBeGreaterThan(35);
      expect(result.signals.length).toBeGreaterThan(0);
    });

    it('should catch zero-width space evasion attempts', async () => {
      // Scam text with zero-width spaces (\u200B) inserted between characters
      const evasiveText = 'U\u200Br\u200Bg\u200Be\u200Bn\u200Bt: Y\u200Bo\u200Bu\u200Br b\u200Ba\u200Bn\u200Bk is locked! Send OTP';
      const normalized = textNormalizer.normalize(evasiveText);

      expect(normalized.cleanedText).toContain('Urgent: Your bank is locked! Send OTP');

      const result = await detectionPipeline.execute({
        type: 'TEXT',
        rawContent: evasiveText,
      });

      expect(result.risk_score).toBeGreaterThan(40);
    });

    it('should catch punctuation-split keywords (e.g. u.r.g.e.n.t w-i-r-e)', async () => {
      const splitText = 'u.r.g.e.n.t w-i-r-e money to this lottery account to receive your prize';
      const normalized = textNormalizer.normalize(splitText);
      expect(normalized.deobfuscatedText).toContain('urgent');
      expect(normalized.deobfuscatedText).toContain('wire');

      const result = await detectionPipeline.execute({
        type: 'TEXT',
        rawContent: splitText,
      });

      expect(result.signals.length).toBeGreaterThan(0);
      expect(result.risk_score).toBeGreaterThanOrEqual(10);
    });
  });

  // =========================================================================
  // 6. Malformed URL Tests
  // =========================================================================
  describe('6. Malformed URL Handling', () => {
    it('should reject URLs with invalid schemes (e.g. ftp, gopher) with 400', async () => {
      const res = await request(app)
        .post('/api/analyze/url')
        .send({ url: 'ftp://ftp.fileserver.org/resource' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });

    it('should reject javascript: pseudo-protocol URIs with 400', async () => {
      const res = await request(app)
        .post('/api/analyze/url')
        .send({ url: 'javascript:alert(document.cookie)' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });

    it('should reject URLs with illegal syntax and control characters with 400', async () => {
      const res = await request(app)
        .post('/api/analyze/url')
        .send({ url: 'https://invalid^domain*chars.com' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });

    it('should reject excessively short URL inputs with 400', async () => {
      const res = await request(app)
        .post('/api/analyze/url')
        .send({ url: 'a' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });
  });

  // =========================================================================
  // 7. Oversized File & Payload Tests
  // =========================================================================
  describe('7. Oversized Payload & File Handling', () => {
    it('should reject text payloads exceeding max character limits with 413', async () => {
      const hugeString = 'X'.repeat(config.payloadLimits.maxTextLengthChars + 500);

      const res = await request(app)
        .post('/api/analyze/text')
        .send({ content: hugeString });

      expect(res.status).toBe(413);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('PAYLOAD_TOO_LARGE');
    });

    it('should handle zero-length empty files with clean 400 FILE_EMPTY', async () => {
      const emptyFilePath = path.join(testDir, 'zero_bytes.txt');
      await fs.promises.writeFile(emptyFilePath, Buffer.alloc(0));

      const res = await request(app)
        .post('/api/analyze/file')
        .attach('file', emptyFilePath);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('FILE_EMPTY');
    });
  });

  // =========================================================================
  // 8. Unsupported & Spoofed File Tests
  // =========================================================================
  describe('8. Unsupported Files & Spoofed Mismatches', () => {
    it('should detect executable disguised with a .png image extension', async () => {
      // Construct PE executable header disguised as PNG
      const disguisedPeBuffer = Buffer.concat([
        Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00'),
        Buffer.from('This program cannot be run in DOS mode.'),
      ]);

      const filePath = path.join(testDir, 'fake_avatar.png');
      await fs.promises.writeFile(filePath, disguisedPeBuffer);

      const result = await secureFileAnalyzer.analyze(filePath, 'fake_avatar.png', 'image/png');

      // Static analyzer and magic bytes must detect the mismatch and high risk
      expect(result.risk_score).toBeGreaterThan(40);
      expect(result.detected_indicators.some((ind) => ind.toLowerCase().includes('executable') || ind.toLowerCase().includes('mismatch'))).toBe(true);
    });

    it('should detect double extension evasion attempts (e.g. invoice.pdf.exe)', async () => {
      const peBuffer = Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00');
      const filePath = path.join(testDir, 'invoice.pdf.exe');
      await fs.promises.writeFile(filePath, peBuffer);

      const result = await secureFileAnalyzer.analyze(filePath, 'invoice.pdf.exe', 'application/octet-stream');

      expect(result.risk_score).toBeGreaterThanOrEqual(60);
      expect(result.detected_indicators.some((ind) => ind.toLowerCase().includes('extension') || ind.toLowerCase().includes('executable'))).toBe(true);
    });
  });

  // =========================================================================
  // 9. Missing Parameters & Invalid Input Types Tests
  // =========================================================================
  describe('9. Missing Parameters & Malformed Payloads', () => {
    it('POST /api/analyze/text should reject empty JSON body {} with 400', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });

    it('POST /api/analyze/url should reject missing url field with 400', async () => {
      const res = await request(app)
        .post('/api/analyze/url')
        .send({ not_a_url: 'something' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });

    it('POST /api/analyze/file should reject requests without multipart file with 400', async () => {
      const res = await request(app)
        .post('/api/analyze/file')
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('FILE_REQUIRED');
    });

    it('POST /api/analyze/text should reject non-string content types (e.g. number)', async () => {
      const res = await request(app)
        .post('/api/analyze/text')
        .send({ content: 123456789 });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });
  });

  // =========================================================================
  // 10. Invalid Authentication Tests
  // =========================================================================
  describe('10. Invalid Authentication Scenarios', () => {
    it('should reject random non-JWT string in Authorization header with 401', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer totally-invalid-random-token-string-xyz');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('UNAUTHORIZED');
      expect(res.body.request_id).toBeDefined();
    });

    it('should reject expired JWT token with 401 UNAUTHORIZED', async () => {
      const expiredToken = jwt.sign(
        { id: 'usr-expired', email: 'expired@example.com', role: 'user' },
        config.jwtSecret,
        { expiresIn: '-10m' }
      );

      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('UNAUTHORIZED');
    });

    it('should reject tampered JWT token payload with 401 UNAUTHORIZED', async () => {
      const validToken = jwt.sign(
        { id: 'usr-tamper', email: 'tamper@example.com', role: 'user' },
        config.jwtSecret,
        { expiresIn: '1h' }
      );

      // Tamper with middle segment (base64 payload)
      const parts = validToken.split('.');
      const tamperedToken = `${parts[0]}.eyJpZCI6ImFkbWluLXRhbXBlciIsInJvbGUiOiJhZG1pbiJ9.${parts[2]}`;

      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${tamperedToken}`);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('UNAUTHORIZED');
    });

    it('should guarantee zero stack trace or internal path leakage on auth errors', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer invalid-token');

      expect(res.status).toBe(401);
      expect(res.body.stack).toBeUndefined();
      expect(res.body.error?.stack).toBeUndefined();
      expect(JSON.stringify(res.body)).not.toMatch(/[a-zA-Z]:\\[\w.-]+/);
    });
  });
});
