import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { createApp } from '../src/app';
import prisma from '../src/database/client';

describe('PinIt Security API Integration Tests', () => {
  const app = createApp();
  const testDir = path.resolve(__dirname, './temp_api_test');
  let authToken = '';
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  let apiKey = '';

  beforeAll(async () => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterAll(async () => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
    await prisma.$disconnect();
  });

  it('GET /api/v1/health should report service status', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
    expect(res.body.services.database).toBe('connected');
  });

  it('GET /api/v1/statistics should return global scan metrics', async () => {
    const res = await request(app).get('/api/v1/statistics');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.statistics.total_scans).toBeDefined();
  });

  it('POST /api/v1/auth/register should create a new user account with API key and JWT', async () => {
    const testEmail = `sec_user_${Date.now()}@example.com`;
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: testEmail, password: 'StrongPassword123!' });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.api_key).toBeDefined();

    authToken = res.body.token;
    apiKey = res.body.user.api_key;
  });

  it('POST /api/v1/urls/scan should accept and enqueue a URL for analysis', async () => {
    const res = await request(app)
      .post('/api/v1/urls/scan')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ url: 'https://example.com' });

    expect(res.status).toBe(202);
    expect(res.body.success).toBe(true);
    expect(res.body.scan_id).toBeDefined();
    expect(res.body.status).toBe('QUEUED');

    // Poll status after async worker finishes
    await new Promise((resolve) => setTimeout(resolve, 500));

    const pollRes = await request(app).get(`/api/v1/urls/scan/${res.body.scan_id}`);
    expect(pollRes.status).toBe(200);
    expect(['QUEUED', 'PROCESSING', 'COMPLETED']).toContain(pollRes.body.status);
  });

  it('POST /api/v1/files/scan should accept an uploaded file and queue it', async () => {
    const filePath = path.join(testDir, 'sample_receipt.txt');
    await fs.promises.writeFile(filePath, 'Official receipt: items purchased total $45.00.');

    const res = await request(app)
      .post('/api/v1/files/scan')
      .set('Authorization', `Bearer ${authToken}`)
      .attach('file', filePath);

    expect(res.status).toBe(202);
    expect(res.body.success).toBe(true);
    expect(res.body.scan_id).toBeDefined();

    // Poll status after worker execution
    await new Promise((resolve) => setTimeout(resolve, 500));

    const pollRes = await request(app).get(`/api/v1/files/scan/${res.body.scan_id}`);
    expect(pollRes.status).toBe(200);
    expect(['QUEUED', 'PROCESSING', 'COMPLETED']).toContain(pollRes.body.status);
  });

  it('GET /api/v1/scans should return paginated historical scans', async () => {
    const res = await request(app)
      .get('/api/v1/scans?page=1&limit=5')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.pagination).toBeDefined();
  });

  it('DELETE /api/v1/scans/:id should reject unauthenticated deletion requests', async () => {
    const res = await request(app).delete('/api/v1/scans/fake-scan-id');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('DELETE /api/v1/scans/:id should allow scan deletion for authorized owner', async () => {
    // Create a temporary scan belonging to authToken user
    const scanRes = await request(app)
      .post('/api/v1/urls/scan')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ url: 'https://test-delete.com' });

    const scanId = scanRes.body.scan_id;

    const delRes = await request(app)
      .delete(`/api/v1/scans/${scanId}`)
      .set('Authorization', `Bearer ${authToken}`);

    expect(delRes.status).toBe(200);
    expect(delRes.body.success).toBe(true);
  });

  it('GET /api/v1/auth/me should authenticate successfully via hashed X-API-Key header', async () => {
    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('X-API-Key', apiKey);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.user.email).toBeDefined();
  });

  it('POST /api/v1/auth/api-key/regenerate should issue a fresh API key and update hash', async () => {
    const res = await request(app)
      .post('/api/v1/auth/api-key/regenerate')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.api_key).toBeDefined();
    expect(res.body.api_key).not.toBe(apiKey);

    // Old API key should now fail
    const oldKeyRes = await request(app)
      .get('/api/v1/auth/me')
      .set('X-API-Key', apiKey);
    expect(oldKeyRes.status).toBe(401);

    // New API key should work
    const newKeyRes = await request(app)
      .get('/api/v1/auth/me')
      .set('X-API-Key', res.body.api_key);
    expect(newKeyRes.status).toBe(200);
  });

  it('POST /api/v1/reports should record a scam report', async () => {
    const res = await request(app)
      .post('/api/v1/reports')
      .send({
        scamType: 'phishing',
        target: 'https://fake-login-bank.xyz',
        description: 'Received SMS pretending to be local bank requesting card PIN.',
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.report_id).toBeDefined();
  });

  it('GET /api/v1/reports should require admin role', async () => {
    // Normal user token should get 403 Forbidden
    const res = await request(app)
      .get('/api/v1/reports')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });
});
