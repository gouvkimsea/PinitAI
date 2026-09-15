import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import { isPrivateOrReservedIpv4, validateUrlForSsrf } from '../src/scanners/url/ssrfGuard';
import { getClientRateLimitKey } from '../src/middleware/rateLimiter';
import { Request } from 'express';

describe('Security Hardening Pass Tests', () => {
  const app = createApp();

  describe('SSRF Guard Hardening', () => {
    it('should block decimal-encoded IP addresses (e.g., 2130706433 = 127.0.0.1)', async () => {
      const res = await validateUrlForSsrf('http://2130706433/');
      expect(res.isSafe).toBe(false);
      expect(res.blockedReason).toMatch(/decimal|ssrf/i);
    });

    it('should block hex-encoded IP addresses (e.g., 0x7f000001 = 127.0.0.1)', async () => {
      const res = await validateUrlForSsrf('http://0x7f000001/');
      expect(res.isSafe).toBe(false);
      expect(res.blockedReason).toMatch(/hexadecimal|ssrf/i);
    });

    it('should block loopback and reserved IPv4 addresses directly', () => {
      expect(isPrivateOrReservedIpv4('127.0.0.1')).toBe(true);
      expect(isPrivateOrReservedIpv4('10.0.0.1')).toBe(true);
      expect(isPrivateOrReservedIpv4('192.168.1.1')).toBe(true);
      expect(isPrivateOrReservedIpv4('169.254.169.254')).toBe(true);
      expect(isPrivateOrReservedIpv4('8.8.8.8')).toBe(false);
    });

    it('should block cloud metadata hostnames', async () => {
      const gcpMetadata = await validateUrlForSsrf('http://metadata.google.internal/computeMetadata/v1/');
      expect(gcpMetadata.isSafe).toBe(false);
      expect(gcpMetadata.blockedReason).toMatch(/ssrf/i);

      const awsMetadata = await validateUrlForSsrf('http://instance-data/latest/meta-data/');
      expect(awsMetadata.isSafe).toBe(false);
      expect(awsMetadata.blockedReason).toMatch(/ssrf/i);
    });

    it('should block local TLDs (.localhost, .local)', async () => {
      const localhostUrl = await validateUrlForSsrf('http://service.localhost/api');
      expect(localhostUrl.isSafe).toBe(false);
      expect(localhostUrl.blockedReason).toMatch(/ssrf/i);

      const localDomain = await validateUrlForSsrf('http://myapp.local/admin');
      expect(localDomain.isSafe).toBe(false);
      expect(localDomain.blockedReason).toMatch(/ssrf/i);
    });

    it('should reject non-HTTP/HTTPS protocols', async () => {
      const fileUrl = await validateUrlForSsrf('file:///etc/passwd');
      expect(fileUrl.isSafe).toBe(false);
      expect(fileUrl.blockedReason).toMatch(/protocol/i);

      const gopherUrl = await validateUrlForSsrf('gopher://127.0.0.1:70/');
      expect(gopherUrl.isSafe).toBe(false);
      expect(gopherUrl.blockedReason).toMatch(/protocol/i);
    });

    it('should allow legitimate public domains', async () => {
      const publicUrl = await validateUrlForSsrf('https://www.google.com/search?q=test');
      expect(publicUrl.isSafe).toBe(true);
    });
  });

  describe('Administrative Route Protection (BOLA/Authorization)', () => {
    it('should reject unauthenticated access to /api/admin/stats with 401', async () => {
      const res = await request(app).get('/api/admin/stats');
      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
    });

    it('should reject unauthenticated access to /api/admin/metrics with 401', async () => {
      const res = await request(app).get('/api/admin/metrics');
      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
    });

    it('should reject unauthenticated access to /api/admin/dataset with 401', async () => {
      const res = await request(app).get('/api/admin/dataset');
      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
    });
  });

  describe('Security Headers (Helmet Hardening)', () => {
    it('should set robust anti-clickjacking and XSS protection headers', async () => {
      const res = await request(app).get('/api/health');
      expect(res.headers['x-frame-options']).toBe('DENY');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
    });
  });

  describe('Rate Limiter Key Generation (Anti-Bypass)', () => {
    it('should generate IP-based key when unauthenticated', () => {
      const req = {
        ip: '198.51.100.1',
        headers: {},
        socket: {},
      } as unknown as Request;

      const key = getClientRateLimitKey(req);
      expect(key).toBe('198.51.100.1');
    });

    it('should bind authenticated user ID to prevent IP rotation bypass', () => {
      const req = {
        ip: '198.51.100.2',
        headers: {},
        user: { id: 'usr-12345', role: 'user' },
      } as unknown as Request;

      const key = getClientRateLimitKey(req);
      expect(key).toBe('user:usr-12345');
    });

    it('should bind API key to prevent IP rotation bypass', () => {
      const req = {
        ip: '198.51.100.3',
        headers: {
          'x-api-key': 'secret-api-key-test',
        },
      } as unknown as Request;

      const key = getClientRateLimitKey(req);
      expect(key).toBe('key:secret-api-key-t');
    });
  });

  describe('Path Traversal & Malicious File Analysis Guard', () => {
    it('should reject or sanitize file analysis with path traversal filenames', async () => {
      const res = await request(app)
        .post('/api/analyze/file')
        .attach('file', Buffer.from('console.log("clean");'), '../../../../etc/passwd');
      
      expect([200, 202, 400]).toContain(res.status);
      const returnedName = res.body?.fileName || res.body?.data?.fileName || res.body?.target || '';
      expect(returnedName).not.toContain('..');
    });
  });
});

