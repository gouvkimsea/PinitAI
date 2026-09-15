import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import prisma from '../src/database/client';
import { textNormalizer } from '../src/pipeline/normalization/textNormalizer';

describe('Production-Readiness Hardening Test Suite', () => {
  const app = createApp();

  describe('1. PII Redaction & Data Protection', () => {
    it('should redact credit card numbers with separators and contiguous digits', () => {
      const input = 'Please pay $50 to credit card 4532-1234-5678-9010 or 4532123456789010 immediately';
      const redacted = textNormalizer.redactPii(input);
      expect(redacted).not.toContain('4532-1234-5678-9010');
      expect(redacted).not.toContain('4532123456789010');
      expect(redacted).toContain('[REDACTED_CARD]');
    });

    it('should redact explicit passwords, pins, and credentials', () => {
      const input = 'Your account login is user@example.com and password: SecretPassword123! or pin: 9948';
      const redacted = textNormalizer.redactPii(input);
      expect(redacted).not.toContain('SecretPassword123!');
      expect(redacted).toContain('[REDACTED_CREDENTIAL]');
    });

    it('should redact one-time verification codes and OTPs', () => {
      const input = 'Your bank verification code: 849201. Do not share your OTP is 192847.';
      const redacted = textNormalizer.redactPii(input);
      expect(redacted).not.toContain('849201');
      expect(redacted).not.toContain('192847');
      expect(redacted).toContain('[REDACTED_OTP]');
    });

    it('should redact US Social Security Numbers', () => {
      const input = 'Confirm identity using SSN 123-45-6789 to prevent suspension';
      const redacted = textNormalizer.redactPii(input);
      expect(redacted).not.toContain('123-45-6789');
      expect(redacted).toContain('[REDACTED_SSN]');
    });
  });

  describe('2. User Account Deletion (GDPR Right to Erasure: DELETE /api/v1/auth/me)', () => {
    const testEmail = `gdpr_test_${Date.now()}@example.com`;
    const testPassword = 'StrongPassword123!';
    let authToken = '';

    beforeAll(async () => {
      const reg = await request(app)
        .post('/api/auth/register')
        .send({ email: testEmail, password: testPassword });
      authToken = reg.body.token;
    });

    it('should reject account deletion if unauthenticated', async () => {
      const res = await request(app)
        .delete('/api/auth/me')
        .send({ password: testPassword });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should reject account deletion if password is missing or wrong', async () => {
      const resNoPass = await request(app)
        .delete('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .send({});

      expect(resNoPass.status).toBe(400);

      const resWrongPass = await request(app)
        .delete('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ password: 'WrongPassword123!' });

      expect(resWrongPass.status).toBe(401);
      expect(resWrongPass.body.error.code).toBe('INVALID_CREDENTIALS');
    });

    it('should permanently delete user account when correct password is provided', async () => {
      const res = await request(app)
        .delete('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ password: testPassword });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('permanently deleted');

      // Verify user no longer exists in DB
      const user = await prisma.user.findUnique({
        where: { email: testEmail },
      });
      expect(user).toBeNull();
    });

    it('should reject subsequent operations with the deleted user token', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(401);
    });
  });

  describe('3. OpenAPI / Swagger Loading with Modern YAML Parser', () => {
    it('should successfully serve the OpenAPI docs endpoint', async () => {
      const res = await request(app).get('/api/docs/');
      // Swagger-UI returns either 200 or 301 redirect to trailing slash
      expect([200, 301, 302]).toContain(res.status);
    });
  });

  describe('4. Self-Service Password Reset Flow', () => {
    const userEmail = `pwd_reset_${Date.now()}@example.com`;
    const oldPassword = 'OldPassword123!';
    const newPassword = 'NewPassword456!';
    let resetToken = '';

    beforeAll(async () => {
      await request(app)
        .post('/api/auth/register')
        .send({ email: userEmail, password: oldPassword });
    });

    it('should issue a reset token for registered user and preserve enumeration safety', async () => {
      const res = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: userEmail });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.reset_token).toBeDefined();
      resetToken = res.body.reset_token;

      // Non-existent email returns 200 OK without token
      const resNonExistent = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: 'nobody_here_12345@example.com' });

      expect(resNonExistent.status).toBe(200);
      expect(resNonExistent.body.reset_token).toBeUndefined();
    });

    it('should reject password reset with invalid or malformed token', async () => {
      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: 'invalid_token_sample_here',
          newPassword,
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should successfully reset password with valid token', async () => {
      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: resetToken,
          newPassword,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('successfully updated');
    });

    it('should verify old password fails and new password succeeds', async () => {
      // Old password fails
      const resOld = await request(app)
        .post('/api/auth/login')
        .send({ email: userEmail, password: oldPassword });
      expect(resOld.status).toBe(401);

      // New password succeeds
      const resNew = await request(app)
        .post('/api/auth/login')
        .send({ email: userEmail, password: newPassword });
      expect(resNew.status).toBe(200);
      expect(resNew.body.token).toBeDefined();
    });

    it('should prevent token replay: already used reset token must be rejected', async () => {
      const resReplay = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: resetToken,
          newPassword: 'AnotherPassword789!',
        });

      expect(resReplay.status).toBe(400);
      expect(resReplay.body.error.code).toBe('EXPIRED_RESET_TOKEN');
    });
  });
});

