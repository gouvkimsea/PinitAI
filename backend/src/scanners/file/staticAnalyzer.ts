import fs from 'fs';
import path from 'path';
import { DetectionItem } from '../../types';
import { detectSuspiciousDoubleExtension } from '../../utils/helpers';

export interface StaticAnalysisResult {
  hasMacro: boolean;
  hasEmbeddedScripts: boolean;
  isDoubleExtension: boolean;
  isSuspiciousExecutable: boolean;
  archiveDetails?: {
    totalFiles: number;
    suspiciousExtensionsFound: string[];
    isZipBombRisk: boolean;
  };
  detections: DetectionItem[];
}

const SUSPICIOUS_SCRIPT_PATTERNS: Array<{
  regex: RegExp;
  ruleId: string;
  title: string;
  category: string;
  severity: 'medium' | 'high' | 'critical';
  description: string;
}> = [
  {
    regex: /powershell(\.exe)?\s+(-(enc|encodedcommand)|-w(indowstyle)?\s+hidden|-ep\s+bypass|-nop)/i,
    ruleId: 'SA-PS-001',
    title: 'Obfuscated PowerShell Execution Command',
    category: 'script_threat',
    severity: 'critical',
    description: 'Detected suspicious PowerShell parameters commonly used to bypass execution policies and download payloads silently.',
  },
  {
    regex: /(wscript\.shell|shell\.application|wscript\.network)/i,
    ruleId: 'SA-SCR-002',
    title: 'Windows Script Host Shell Invocation',
    category: 'script_threat',
    severity: 'high',
    description: 'Detected programmatic shell invocation capable of executing arbitrary command line instructions.',
  },
  {
    regex: /certutil(\.exe)?\s+(-urlcache\s+-split\s+-f|-decode)/i,
    ruleId: 'SA-DL-003',
    title: 'Living-off-the-Land Downloader (CertUtil)',
    category: 'script_threat',
    severity: 'critical',
    description: 'Detected certutil misuse pattern used by threat actors to stealthily download or decode binary malware.',
  },
  {
    regex: /(bitsadmin(\.exe)?\s+\/transfer|curl\s+-[oO]|wget\s+-O)/i,
    ruleId: 'SA-DL-004',
    title: 'Automated Payload Downloader Pattern',
    category: 'script_threat',
    severity: 'high',
    description: 'Detected automated network download command pattern inside file contents.',
  },
  {
    regex: /(auto_?open|document_?open|workbook_?open|vbaProject\.bin|autoexec)/i,
    ruleId: 'SA-MCR-005',
    title: 'Embedded Office Auto-Execution Macro',
    category: 'macro_threat',
    severity: 'high',
    description: 'Found auto-executing macro triggers (VBA) inside document structures. Malicious documents often use auto-run macros to infect systems upon opening.',
  },
  {
    regex: /eval\s*\(\s*(base64_decode|unescape|fromcharcode|window\.atob)/i,
    ruleId: 'SA-OBF-006',
    title: 'Dynamic Code Execution with Decoded String',
    category: 'obfuscation',
    severity: 'critical',
    description: 'Detected dynamic code execution with in-memory decoded strings (eval/atob/fromcharcode), typical of obfuscated droppers.',
  },
];

/**
 * Performs static pattern and structural analysis without executing the file.
 */
export async function analyzeFileStatically(
  filePath: string,
  filename: string,
  fileSize: number
): Promise<StaticAnalysisResult> {
  const detections: DetectionItem[] = [];
  const ext = path.extname(filename).replace('.', '').toLowerCase();

  // 1. Double Extension Check
  const doubleExt = detectSuspiciousDoubleExtension(filename);
  if (doubleExt.isDoubleExtension) {
    detections.push({
      engine: 'StaticAnalyzer',
      category: 'masquerading',
      severity: 'critical',
      ruleId: 'SA-EXT-001',
      title: 'Deceptive Double File Extension',
      description: `File '${filename}' uses a deceptive double extension (.${doubleExt.disguisedExtension}.${doubleExt.actualExtension}) to trick users into opening an executable file disguised as a document or image.`,
      details: doubleExt,
    });
  }

  // 2. High Risk Standalone Extensions
  const highRiskExecutables = new Set(['exe', 'scr', 'bat', 'vbs', 'cmd', 'ps1', 'hta', 'cpl', 'jar', 'pif', 'com']);
  if (highRiskExecutables.has(ext)) {
    detections.push({
      engine: 'StaticAnalyzer',
      category: 'executable_risk',
      severity: 'medium',
      ruleId: 'SA-EXT-002',
      title: 'Direct Executable File Format',
      description: `The file is an executable format (.${ext}). Direct executables should be handled with extreme caution and verified before running.`,
      details: { extension: ext },
    });
  }

  // 3. Scan content for suspicious strings (scanning first 4MB for safety & performance)
  let hasMacro = false;
  let hasEmbeddedScripts = false;
  const scanLimit = Math.min(fileSize, 4 * 1024 * 1024);

  const fd = await fs.promises.open(filePath, 'r');
  const buffer = Buffer.alloc(scanLimit);
  let bytesRead = 0;
  try {
    const readResult = await fd.read(buffer, 0, scanLimit, 0);
    bytesRead = readResult.bytesRead;
  } finally {
    await fd.close();
  }

  const fileString = buffer.subarray(0, bytesRead).toString('latin1');

  for (const pattern of SUSPICIOUS_SCRIPT_PATTERNS) {
    if (pattern.regex.test(fileString)) {
      if (pattern.category === 'macro_threat') {
        hasMacro = true;
      } else {
        hasEmbeddedScripts = true;
      }

      detections.push({
        engine: 'StaticAnalyzer',
        category: pattern.category,
        severity: pattern.severity,
        ruleId: pattern.ruleId,
        title: pattern.title,
        description: pattern.description,
      });
    }
  }

  // 4. Archive inspection (safe header scanning for ZIP without extracting)
  let archiveDetails: StaticAnalysisResult['archiveDetails'];
  if (ext === 'zip' || ext === 'apk' || ext === 'jar') {
    archiveDetails = inspectZipHeaders(buffer);
    if (archiveDetails.suspiciousExtensionsFound.length > 0) {
      detections.push({
        engine: 'StaticAnalyzer',
        category: 'hidden_payload',
        severity: 'high',
        ruleId: 'SA-ZIP-001',
        title: 'Dangerous Executable Inside Archive',
        description: `Archive contains suspicious executable files: [${archiveDetails.suspiciousExtensionsFound.join(', ')}]. Attackers frequently archive malware to bypass email filters.`,
        details: archiveDetails,
      });
    }
    if (archiveDetails.isZipBombRisk) {
      detections.push({
        engine: 'StaticAnalyzer',
        category: 'dos_risk',
        severity: 'critical',
        ruleId: 'SA-ZIP-002',
        title: 'Potential Zip Bomb / Decompression Hazard',
        description: 'Detected abnormal compression ratios or excessive file counts inside archive, posing a Denial of Service risk.',
        details: archiveDetails,
      });
    }
  }

  return {
    hasMacro,
    hasEmbeddedScripts,
    isDoubleExtension: doubleExt.isDoubleExtension,
    isSuspiciousExecutable: highRiskExecutables.has(ext),
    archiveDetails,
    detections,
  };
}

/**
 * Parses ZIP Central Directory safely without decompression.
 */
function inspectZipHeaders(buffer: Buffer): {
  totalFiles: number;
  suspiciousExtensionsFound: string[];
  isZipBombRisk: boolean;
} {
  const suspiciousExts = new Set(['exe', 'bat', 'vbs', 'scr', 'ps1', 'cmd', 'hta', 'cpl']);
  const foundDangerous: Set<string> = new Set();
  let totalFiles = 0;

  // Search for Local File Header signature: 50 4B 03 04
  for (let i = 0; i < buffer.length - 30; i++) {
    if (buffer[i] === 0x50 && buffer[i + 1] === 0x4b && buffer[i + 2] === 0x03 && buffer[i + 3] === 0x04) {
      totalFiles++;
      const fileNameLen = buffer.readUInt16LE(i + 26);
      if (fileNameLen > 0 && i + 30 + fileNameLen <= buffer.length) {
        const entryName = buffer.subarray(i + 30, i + 30 + fileNameLen).toString('utf8');
        const entryExt = path.extname(entryName).replace('.', '').toLowerCase();
        if (suspiciousExts.has(entryExt)) {
          foundDangerous.add(entryName);
        }
      }
    }
  }

  return {
    totalFiles,
    suspiciousExtensionsFound: Array.from(foundDangerous).slice(0, 10),
    isZipBombRisk: totalFiles > 5000,
  };
}
