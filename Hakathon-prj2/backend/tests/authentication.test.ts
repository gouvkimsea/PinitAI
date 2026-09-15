import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app';
import { config } from '../src/config';
import prisma from '../src/database/client';

describe('Dedicated Authentication, Token Lifecycle & RBAC Test Suite', () => {
  const app = createApp();
  const testTimestamp = Date.now();
  const testUserEmail = `auth_tester_${testTimestamp}@example.com`;
  const testUserPassword = 'ValidPassword123!';
  let userToken = '';
  let userApiKey = '';
  let userId = '';

  const testAdminEmail = `admin_tester_${testTimestamp}@example.com`;
  let adminToken = '';
  let adminId = '';

  beforeAll(async () => {
    // Create an admin user directly for RBAC testing
    const adminUser = await prisma.user.create({
      data: {
        email: testAdminEmail,
        passwordHash: 'hashed_admin_pass',
        apiKeyHash: 'hashed_admin_key',
        role: 'admin',
      },
    });

    adminId = adminUser.id;
    adminToken = jwt.sign(
      { id: adminUser.id, email: adminUser.email, role: adminUser.role },
      config.jwtSecret,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    await prisma.securityEvent.deleteMany({
      where: {
        targetResource: { in: ['/api/v1/auth/login', '/api/auth/login'] },
      },
    }).catch(() => {});

    await prisma.user.deleteMany({
      where: {
        email: { in: [testUserEmail, testAdminEmail] },
      },
    }).catch(() => {});

    await prisma.$disconnect();
  });

  describe('1. User Registration Contract & Validation', () => {
    it('POST /api/v1/auth/register should create a user and return token & api_key', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: testUserEmail,
          password: testUserPassword,
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.user).toBeDefined();
      expect(res.body.user.email).toBe(testUserEmail.toLowerCase());
      expect(res.body.user.role).toBe('user');
      expect(res.body.token).toBeDefined();
      expect(res.body.user.api_key).toMatch(/^pk_[a-f0-9]{48}$/);

      userToken = res.body.token;
      userApiKey = res.body.user.api_key;
      userId = res.body.user.id;

      // Verify password was hashed and never stored in plaintext
      const dbUser = await prisma.user.findUnique({ where: { id: userId } });
      expect(dbUser?.passwordHash).not.toBe(testUserPassword);
      expect(dbUser?.passwordHash).toMatch(/^\$2[aby]\$/); // bcrypt hash
    });

    it('POST /api/v1/auth/register should reject duplicate email registration with 409', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: testUserEmail,
          password: 'AnotherPassword123!',
        });

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('USER_ALREADY_EXISTS');
      expect(res.body.message).toContain('already registered');
    });

    it('POST /api/v1/auth/register should reject invalid email address formats', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'not-an-email',
          password: testUserPassword,
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });

    it('POST /api/v1/auth/register should reject passwords shorter than 8 characters', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: `short_pw_${Date.now()}@example.com`,
          password: 'short',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });
  });

  describe('2. User Login & Credential Verification', () => {
    it('POST /api/v1/auth/login should authenticate with valid credentials', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUserEmail,
          password: testUserPassword,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.token).toBeDefined();
      expect(res.body.user.email).toBe(testUserEmail.toLowerCase());
      // Raw API key is not revealed upon login for security (only masked preview)
      expect(res.body.user.api_key).toBe('pk_****************');
    });

    it('POST /api/v1/auth/login should reject incorrect password with 401', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUserEmail,
          password: 'WrongPassword999!',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('INVALID_CREDENTIALS');
    });

    it('POST /api/v1/auth/login should reject non-existent user email with 401', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent_ghost_user@example.com',
          password: 'SomePassword123!',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('INVALID_CREDENTIALS');
    });

    it('POST /api/v1/auth/login should reject empty body with 400', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('VALIDATION_ERROR');
    });
  });

  describe('3. JWT Token Lifecycle, Expiration & Tampering Defense', () => {
    it('GET /api/v1/auth/me should return user profile with valid Bearer token', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.user.id).toBe(userId);
      expect(res.body.user.email).toBe(testUserEmail.toLowerCase());
    });

    it('GET /api/v1/auth/me should reject expired JWT tokens with 401', async () => {
      const expiredToken = jwt.sign(
        { id: userId, email: testUserEmail, role: 'user' },
        config.jwtSecret,
        { expiresIn: '-1s' } // Expired 1 second ago
      );

      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('UNAUTHORIZED');
    });

    it('GET /api/v1/auth/me should reject JWTs with forged or tampered signatures', async () => {
      const forgedToken = jwt.sign(
        { id: userId, email: testUserEmail, role: 'admin' },
        'WRONG_FORGED_SECRET_KEY',
        { expiresIn: '1h' }
      );

      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${forgedToken}`);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('UNAUTHORIZED');
    });

    it('GET /api/v1/auth/me should reject malformed Authorization headers', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'InvalidFormatWithoutBearerToken');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('UNAUTHORIZED');
    });

    it('GET /api/v1/auth/me should reject requests missing Authorization headers', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('UNAUTHORIZED');
    });
  });

  describe('4. API Key Lifecycle & Invalidation', () => {
    it('should authenticate API requests via x-api-key header', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('x-api-key', userApiKey);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.user.id).toBe(userId);
    });

    it('should reject invalid or non-existent x-api-key headers with 401', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('x-api-key', 'pk_invalid_key_that_does_not_exist_in_db_000000000000');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('UNAUTHORIZED');
    });

    it('POST /api/v1/auth/api-key/regenerate should issue new key and invalidate the old key', async () => {
      const regenRes = await request(app)
        .post('/api/v1/auth/api-key/regenerate')
        .set('Authorization', `Bearer ${userToken}`);

      expect(regenRes.status).toBe(200);
      expect(regenRes.body.success).toBe(true);
      expect(regenRes.body.api_key).toBeDefined();
      expect(regenRes.body.api_key).toMatch(/^pk_[a-f0-9]{48}$/);

      const newApiKey = regenRes.body.api_key;
      expect(newApiKey).not.toBe(userApiKey);

      // Old API key must now be rejected
      const oldKeyRes = await request(app)
        .get('/api/v1/auth/me')
        .set('x-api-key', userApiKey);
      expect(oldKeyRes.status).toBe(401);

      // New API key must succeed
      const newKeyRes = await request(app)
        .get('/api/v1/auth/me')
        .set('x-api-key', newApiKey);
      expect(newKeyRes.status).toBe(200);
      expect(newKeyRes.body.user.id).toBe(userId);
    });
  });

  describe('5. Role-Based Access Control (RBAC) & Privilege Boundaries', () => {
    it('should prevent standard user from accessing admin endpoints (403 Forbidden)', async () => {
      const res = await request(app)
        .get('/api/admin/stats')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('FORBIDDEN');
    });

    it('should allow admin user to access admin endpoints (200 OK)', async () => {
      const res = await request(app)
        .get('/api/admin/stats')
        .set('Authorization', `Bearer ${adminToken}`);

      // 200 or successful execution through proxy/mock
      expect([200, 502]).toContain(res.status); // 502 only if Python AI microservice isn't running
      if (res.status === 200) {
        expect(res.body).toBeDefined();
      }
    });

    it('should prevent standard user from deleting other users scans', async () => {
      // Create a scan belonging to admin
      const scan = await prisma.scan.create({
        data: {
          type: 'MESSAGE',
          target: 'Admin target item',
          status: 'COMPLETED',
          userId: adminId,
        },
      });

      // Attempt to delete with standard user credentials
      const res = await request(app)
        .delete(`/api/v1/scans/${scan.id}`)
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error_code).toBe('FORBIDDEN');

      // Cleanup
      await prisma.scan.delete({ where: { id: scan.id } }).catch(() => {});
    });
  });
});
