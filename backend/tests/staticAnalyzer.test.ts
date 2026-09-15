import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeFileStatically } from '../src/scanners/file/staticAnalyzer';

describe('Static File Analyzer', () => {
  const testDir = path.resolve(__dirname, './temp_static_test');

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

  it('should detect malicious double extensions (e.g. statement.pdf.exe)', async () => {
    const doubleExtPath = path.join(testDir, 'statement.pdf.exe');
    await fs.promises.writeFile(doubleExtPath, 'benign content');

    const result = await analyzeFileStatically(doubleExtPath, 'statement.pdf.exe', 14);
    expect(result.isDoubleExtension).toBe(true);
    expect(result.detections.some((d) => d.category === 'masquerading')).toBe(true);
  });

  it('should detect encoded PowerShell payload commands', async () => {
    const scriptPath = path.join(testDir, 'setup.bat');
    const content = '@echo off\npowershell -encodedCommand JABhAD0... -windowstyle hidden\n';
    await fs.promises.writeFile(scriptPath, content);

    const result = await analyzeFileStatically(scriptPath, 'setup.bat', content.length);
    expect(result.hasEmbeddedScripts).toBe(true);
    expect(result.detections.some((d) => d.ruleId === 'SA-PS-001')).toBe(true);
  });

  it('should detect auto-running Office macro references', async () => {
    const docPath = path.join(testDir, 'invoice.doc');
    const content = 'Sub Auto_Open()\nMsgBox "Update required"\nShell "cmd.exe"\nEnd Sub';
    await fs.promises.writeFile(docPath, content);

    const result = await analyzeFileStatically(docPath, 'invoice.doc', content.length);
    expect(result.hasMacro).toBe(true);
    expect(result.detections.some((d) => d.ruleId === 'SA-MCR-005')).toBe(true);
  });

  it('should report no detections for clean plain text files', async () => {
    const cleanPath = path.join(testDir, 'notes.txt');
    const content = 'Meeting notes: discuss backend design, database architecture, and security policies.';
    await fs.promises.writeFile(cleanPath, content);

    const result = await analyzeFileStatically(cleanPath, 'notes.txt', content.length);
    expect(result.hasMacro).toBe(false);
    expect(result.hasEmbeddedScripts).toBe(false);
    expect(result.isDoubleExtension).toBe(false);
    expect(result.detections.length).toBe(0);
  });
});
