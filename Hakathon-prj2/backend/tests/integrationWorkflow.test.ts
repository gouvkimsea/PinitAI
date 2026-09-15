import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app';
import { config } from '../src/config';
import prisma from '../src/database/client';
import { aiCircuitBreaker } from '../src/modules/ai/circuitBreaker';

describe('End-to-End Production Integration Workflow & Lifecycle Tests', () => {
  const app = createApp();
  const testId = Date.now();
  const userEmail = `integration_user_${testId}@example.com`;
  const adminEmail = `integration_admin_${testId}@example.com`;
  const strongPassword = 'P@ssword1234!';

  let userToken = '';
  let userId = '';
  let adminToken = '';
  let adminId = '';

  beforeAll(async () => {
    // Create admin user directly in DB
    const admin = await prisma.user.create({
      data: {
        email: adminEmail,
        passwordHash: '$2a$12$eImiTXuWVxfM37uY4JANjOL.oUT1nqFCaswtZVu3a54nE3a',
        role: 'admin',
        status: 'active',
      },
    });
    adminId = admin.id;
    adminToken = jwt.sign(
      { id: admin.id, email: admin.email, role: admin.role },
      config.jwtSecret,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    await prisma.scan.deleteMany({
      where: { userId: { in: [userId, adminId] } },
    }).catch(() => {});

    await prisma.user.deleteMany({
      where: { email: { in: [userEmail, adminEmail] } },
    }).catch(() => {});

    await prisma.$disconnect();
  });

  describe('1. Authentication, Password Complexity & Token Revocation Lifecycle', () => {
    it('should reject registration if password does not meet complexity requirements', async () => {
      // Missing uppercase and number
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: `weak_${testId}@example.com`,
          password: 'lowercaseonly',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should register a new user with valid complex password and return token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: userEmail,
          password: strongPassword,
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.token).toBeDefined();
      expect(res.body.user.email).toBe(userEmail);
      userId = res.body.user.id;
      userToken = res.body.token;
    });

    it('should authenticate user via login endpoint and return fresh token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: userEmail,
          password: strongPassword,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.token).toBeDefined();
      userToken = res.body.token;
    });

    it('should allow accessing protected profile endpoint with valid token', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.user.email).toBe(userEmail);
    });

    it('should refresh an active session token via /auth/refresh', async () => {
      const res = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.token).toBeDefined();
      // Update token to the refreshed one
      userToken = res.body.token;
    });

    it('should revoke token upon logout and reject subsequent access with 401', async () => {
      const logoutRes = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${userToken}`);

      expect(logoutRes.status).toBe(200);
      expect(logoutRes.body.success).toBe(true);

      // Attempting to reuse revoked token must be rejected
      const profileRes = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${userToken}`);

      expect(profileRes.status).toBe(401);
    });
  });

  describe('2. Role Hierarchy & Access Control Verification', () => {
    let reauthenticatedUserToken = '';

    beforeAll(async () => {
      // Re-login user after previous test logged out
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: userEmail, password: strongPassword });
      reauthenticatedUserToken = loginRes.body.token;
    });

    it('should deny standard user access to admin retention purge (403 Forbidden)', async () => {
      const res = await request(app)
        .delete('/api/v1/admin/retention/purge')
        .set('Authorization', `Bearer ${reauthenticatedUserToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error_code).toBe('FORBIDDEN');
    });

    it('should allow admin user to access admin retention policy (200 OK)', async () => {
      const res = await request(app)
        .get('/api/v1/admin/retention/policy')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.policy).toBeDefined();
    });

    it('should execute data retention purge successfully when called by admin', async () => {
      const res = await request(app)
        .delete('/api/v1/admin/retention/purge?days=90')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.result).toBeDefined();
      expect(res.body.result.retentionDays).toBe(90);
    });
  });

  describe('3. Scan Lifecycle & Retrieval Workflow', () => {
    let activeToken = '';

    beforeAll(async () => {
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: userEmail, password: strongPassword });
      activeToken = loginRes.body.token;
    });

    it('should submit a text analysis scan and return scan result', async () => {
      const res = await request(app)
        .post('/api/v1/analyze/text')
        .set('Authorization', `Bearer ${activeToken}`)
        .send({
          content: 'Hello, your package is ready for delivery at the local post office.',
        });

      expect([200, 202]).toContain(res.status);
      expect(res.body.success).toBe(true);
      const scanId = res.body.scan_id || res.body.id;
      expect(scanId).toBeDefined();

      // Retrieve scan by ID
      const getRes = await request(app)
        .get(`/api/v1/scans/${scanId}`)
        .set('Authorization', `Bearer ${activeToken}`);

      expect(getRes.status).toBe(200);
      expect(getRes.body.success).toBe(true);
    });

    it('should list scans for authenticated user in history', async () => {
      const res = await request(app)
        .get('/api/v1/scans')
        .set('Authorization', `Bearer ${activeToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
    });
  });

  describe('4. AI Circuit Breaker Fault Tolerance', () => {
    it('should initially be in CLOSED state and record failures', () => {
      expect(aiCircuitBreaker.isOpen()).toBe(false);

      // Record 5 failures to trip breaker
      for (let i = 0; i < 5; i++) {
        aiCircuitBreaker.recordFailure('Simulated AI timeout');
      }

      // Circuit should now be OPEN
      expect(aiCircuitBreaker.isOpen()).toBe(true);
      expect(aiCircuitBreaker.getState()).toBe('OPEN');

      // Recover breaker
      aiCircuitBreaker.recordSuccess();
      expect(aiCircuitBreaker.isOpen()).toBe(false);
      expect(aiCircuitBreaker.getState()).toBe('CLOSED');
    });
  });
});
