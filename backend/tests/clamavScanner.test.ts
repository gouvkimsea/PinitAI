import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanWithClamAV } from '../src/scanners/antivirus/clamavScanner';

describe('Antivirus Engine (ClamAV & Fallback Signatures)', () => {
  const testDir = path.resolve(__dirname, './temp_av_test');

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

  it('should detect the industry-standard EICAR antivirus test file', async () => {
    const eicarPath = path.join(testDir, 'eicar.com');
    const eicarStr = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    await fs.promises.writeFile(eicarPath, eicarStr);

    const result = await scanWithClamAV(eicarPath);
    expect(result.isInfected).toBe(true);
    expect(result.virusName).toBeDefined();
    expect(result.detections.length).toBeGreaterThan(0);
    expect(result.detections[0].category).toBe('virus_detection');
    expect(result.detections[0].severity).toBe('critical');
  });

  it('should verify clean files are not flagged as infected', async () => {
    const cleanPath = path.join(testDir, 'safe.txt');
    await fs.promises.writeFile(cleanPath, 'This is a completely safe clean file without any threats.');

    const result = await scanWithClamAV(cleanPath);
    expect(result.isInfected).toBe(false);
    expect(result.detections.length).toBe(0);
  });
});
