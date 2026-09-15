import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeMagicBytes } from '../src/scanners/file/magicBytes';

describe('Magic Bytes Scanner', () => {
  const testDir = path.resolve(__dirname, './temp_magic_test');

  beforeAll(() => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterAll(() => {
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('should detect legitimate PDF magic bytes', async () => {
    const pdfPath = path.join(testDir, 'test.pdf');
    // %PDF-1.4 header
    const pdfBuffer = Buffer.from('%PDF-1.4\n%âãÏÓ\n1 0 obj\n<<>>\nendobj', 'binary');
    await fs.promises.writeFile(pdfPath, pdfBuffer);

    const result = await analyzeMagicBytes(pdfPath, 'pdf', 'application/pdf');
    expect(result.detectedType).toBe('PDF Document');
    expect(result.isMismatch).toBe(false);
    expect(result.detections.length).toBe(0);
  });

  it('should detect an executable masquerading as a PDF (MIME mismatch)', async () => {
    const fakePdfPath = path.join(testDir, 'invoice.pdf');
    // MZ header (Windows executable signature)
    const exeBuffer = Buffer.alloc(128);
    exeBuffer[0] = 0x4d; // 'M'
    exeBuffer[1] = 0x5a; // 'Z'
    await fs.promises.writeFile(fakePdfPath, exeBuffer);

    const result = await analyzeMagicBytes(fakePdfPath, 'pdf', 'application/pdf');
    expect(result.detectedType).toBe('Windows Executable');
    expect(result.isMismatch).toBe(true);
    expect(result.detections.some((d) => d.category === 'extension_mismatch')).toBe(true);
    expect(result.detections[0].severity).toBe('critical');
  });

  it('should detect legitimate PNG magic bytes', async () => {
    const pngPath = path.join(testDir, 'image.png');
    // 89 50 4E 47 0D 0A 1A 0A
    const pngBuffer = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
    await fs.promises.writeFile(pngPath, pngBuffer);

    const result = await analyzeMagicBytes(pngPath, 'png', 'image/png');
    expect(result.detectedType).toBe('PNG Image');
    expect(result.isMismatch).toBe(false);
  });
});
