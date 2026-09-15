import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app';
import { config } from '../src/config';
import prisma from '../src/database/client';
import { scamIntelligenceService } from '../src/modules/intelligence';

describe('Scam Intelligence API Endpoints (/api/intelligence/*)', () => {
  const app = createApp();
  let adminToken = '';

  beforeAll(async () => {
    await scamIntelligenceService.initialize();
    await scamIntelligenceService.seedCatalog(true);

    adminToken = jwt.sign(
      { id: 'admin-test-id', email: 'admin@scamcheck.io', role: 'admin' },
      config.jwtSecret,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('GET /api/intelligence/categories returns all 10 supported scam categories', async () => {
    const res = await request(app).get('/api/intelligence/categories');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.supported_categories)).toBe(true);

    const categories = res.body.supported_categories;
    expect(categories).toContain('phishing');
    expect(categories).toContain('fake_investment');
    expect(categories).toContain('fake_job');
    expect(categories).toContain('romance_scam');
    expect(categories).toContain('payment_scam');
    expect(categories).toContain('account_takeover');
    expect(categories).toContain('impersonation');
    expect(categories).toContain('lottery_scam');
    expect(categories).toContain('cryptocurrency_scam');
    expect(categories).toContain('tech_support_scam');
  });

  it('POST /api/intelligence/compare evaluates content against scam patterns', async () => {
    const res = await request(app)
      .post('/api/intelligence/compare')
      .send({
        content: 'Exclusive giveaway: Send 1 BTC and double your crypto today!',
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.matched).toBe(true);
    expect(res.body.data.categories_detected).toContain('cryptocurrency_scam');
    expect(res.body.data.highest_severity).toBe('critical');
    expect(res.body.data.scam_score).toBeGreaterThan(0);
    expect(res.body.data.recommended_action).toBeDefined();
    expect(res.body.data.execution_time_ms).toBeGreaterThanOrEqual(0);
  });

  it('GET /api/intelligence/patterns lists patterns with pagination', async () => {
    const res = await request(app)
      .get('/api/intelligence/patterns?limit=10&offset=0');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.pagination.total).toBeGreaterThan(0);
    expect(res.body.pagination.limit).toBe(10);
  });

  it('GET /api/intelligence/patterns?category=fake_investment filters by category', async () => {
    const res = await request(app)
      .get('/api/intelligence/patterns?category=fake_investment');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    for (const item of res.body.data) {
      expect(item.category).toBe('fake_investment');
    }
  });

  it('Admin CRUD workflow: create, read, update, delete scam pattern', async () => {
    const uniqueToken = `api_crud_token_${Date.now()}`;

    // 1. Create Pattern (POST)
    const createRes = await request(app)
      .post('/api/intelligence/patterns')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        pattern: `\\b${uniqueToken}\\b`,
        category: 'tech_support_scam',
        severity: 'high',
        description: 'New emergent tech support remote desktop lure',
        source: 'threat_bulletin_2026',
        status: 'active',
      });

    expect(createRes.status).toBe(201);
    expect(createRes.body.success).toBe(true);
    const newId = createRes.body.data.id;
    expect(newId).toBeDefined();

    // 2. Read Pattern by ID (GET)
    const getRes = await request(app).get(`/api/intelligence/patterns/${newId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.data.pattern).toBe(`\\b${uniqueToken}\\b`);
    expect(getRes.body.data.category).toBe('tech_support_scam');

    // 3. Immediately test comparison with the new dynamic pattern
    const compareRes = await request(app)
      .post('/api/intelligence/compare')
      .send({ content: `Urgent message with ${uniqueToken} present.` });
    expect(compareRes.status).toBe(200);
    expect(compareRes.body.data.matched).toBe(true);
    expect(compareRes.body.data.categories_detected).toContain('tech_support_scam');

    // 4. Update Pattern (PUT)
    const updateRes = await request(app)
      .put(`/api/intelligence/patterns/${newId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        severity: 'critical',
        description: 'Escalated to critical after active exploitation observed',
      });

    expect(updateRes.status).toBe(200);
    expect(updateRes.body.data.severity).toBe('critical');

    // 5. Delete Pattern (DELETE)
    const deleteRes = await request(app)
      .delete(`/api/intelligence/patterns/${newId}`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(deleteRes.status).toBe(200);
    expect(deleteRes.body.success).toBe(true);

    // 6. Verify deleted pattern 404
    const getDeletedRes = await request(app).get(`/api/intelligence/patterns/${newId}`);
    expect(getDeletedRes.status).toBe(404);
  });
});
