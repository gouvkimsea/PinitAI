import fs from 'fs';
import { DetectionItem } from '../../types';

export interface MagicByteResult {
  detectedMimeType: string;
  detectedType: string;
  fileHeaderHex: string;
  isExecutable: boolean;
  isArchive: boolean;
  isScript: boolean;
  isMismatch: boolean;
  detections: DetectionItem[];
}

interface Signature {
  bytes: number[];
  offset?: number;
  mime: string;
  type: string;
  isExecutable?: boolean;
  isArchive?: boolean;
}

const SIGNATURES: Signature[] = [
  // Windows Portable Executable (EXE, DLL, SYS, SCR)
  { bytes: [0x4d, 0x5a], mime: 'application/x-dosexec', type: 'Windows Executable', isExecutable: true },
  // Linux ELF
  { bytes: [0x7f, 0x45, 0x4c, 0x46], mime: 'application/x-executable', type: 'Linux ELF Executable', isExecutable: true },
  // Mach-O (macOS)
  { bytes: [0xfe, 0xed, 0xfa, 0xce], mime: 'application/x-mach-binary', type: 'Mach-O 32-bit', isExecutable: true },
  { bytes: [0xfe, 0xed, 0xfa, 0xcf], mime: 'application/x-mach-binary', type: 'Mach-O 64-bit', isExecutable: true },
  { bytes: [0xcf, 0xfa, 0xed, 0xfe], mime: 'application/x-mach-binary', type: 'Mach-O 64-bit reverse', isExecutable: true },
  // PDF
  { bytes: [0x25, 0x50, 0x44, 0x46], mime: 'application/pdf', type: 'PDF Document' },
  // ZIP / Office OpenXML (.docx, .xlsx, .pptx)
  { bytes: [0x50, 0x4b, 0x03, 0x04], mime: 'application/zip', type: 'ZIP Archive', isArchive: true },
  { bytes: [0x50, 0x4b, 0x05, 0x06], mime: 'application/zip', type: 'ZIP Archive (empty)', isArchive: true },
  // MS Compound Document Format (Legacy doc, xls, ppt)
  { bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], mime: 'application/x-ole-storage', type: 'Legacy MS Office Document' },
  // RAR
  { bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], mime: 'application/x-rar-compressed', type: 'RAR Archive', isArchive: true },
  // 7-Zip
  { bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], mime: 'application/x-7z-compressed', type: '7-Zip Archive', isArchive: true },
  // Tar
  { bytes: [0x75, 0x73, 0x74, 0x61, 0x72], offset: 257, mime: 'application/x-tar', type: 'TAR Archive', isArchive: true },
  // GZIP
  { bytes: [0x1f, 0x8b, 0x08], mime: 'application/gzip', type: 'GZIP Archive', isArchive: true },
  // Images
  { bytes: [0xff, 0xd8, 0xff], mime: 'image/jpeg', type: 'JPEG Image' },
  { bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], mime: 'image/png', type: 'PNG Image' },
  { bytes: [0x47, 0x49, 0x46, 0x38], mime: 'image/gif', type: 'GIF Image' },
  { bytes: [0x52, 0x49, 0x46, 0x46], mime: 'image/webp', type: 'RIFF WebP / Media' },
  // Shell Shebang
  { bytes: [0x23, 0x21], mime: 'text/x-shellscript', type: 'Script' },
];

/**
 * Reads header bytes and determines true file format, catching extension spoofing attacks.
 */
export async function analyzeMagicBytes(
  filePath: string,
  declaredExtension: string,
  declaredMimeType: string
): Promise<MagicByteResult> {
  const detections: DetectionItem[] = [];
  const fd = await fs.promises.open(filePath, 'r');
  const buffer = Buffer.alloc(512);
  const { bytesRead } = await fd.read(buffer, 0, 512, 0);
  await fd.close();

  const fileHeaderHex = buffer.subarray(0, Math.min(16, bytesRead)).toString('hex').toUpperCase();

  let matchedSig: Signature | null = null;

  for (const sig of SIGNATURES) {
    const offset = sig.offset || 0;
    if (bytesRead < offset + sig.bytes.length) continue;

    let matches = true;
    for (let i = 0; i < sig.bytes.length; i++) {
      if (buffer[offset + i] !== sig.bytes[i]) {
        matches = false;
        break;
      }
    }

    if (matches) {
      matchedSig = sig;
      break;
    }
  }

  const cleanExt = declaredExtension.replace('.', '').toLowerCase();
  const detectedMime = matchedSig ? matchedSig.mime : declaredMimeType || 'application/octet-stream';
  const detectedType = matchedSig ? matchedSig.type : 'Unknown Binary / Text';
  const isExecutable = matchedSig?.isExecutable || ['exe', 'scr', 'bat', 'cmd', 'vbs', 'ps1'].includes(cleanExt);
  const isArchive = matchedSig?.isArchive || ['zip', 'rar', '7z', 'tar', 'gz'].includes(cleanExt);
  const isScript = matchedSig?.type === 'Script' || ['sh', 'bash', 'py', 'js', 'vbs', 'bat', 'ps1'].includes(cleanExt);

  // Check for dangerous MIME/extension mismatches (e.g. EXE renamed to PDF or PNG)
  let isMismatch = false;
  const imageExts = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp']);
  const docExts = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt']);

  if (matchedSig?.isExecutable && (imageExts.has(cleanExt) || docExts.has(cleanExt))) {
    isMismatch = true;
    detections.push({
      engine: 'MagicBytesEngine',
      category: 'extension_mismatch',
      severity: 'critical',
      ruleId: 'MB-001',
      title: 'Disguised Executable Binary Detected',
      description: `File claims to be a .${cleanExt} file (${declaredMimeType}), but binary header contains a ${matchedSig.type} magic signature (${fileHeaderHex.substring(0, 8)}). This is a common malware delivery technique.`,
      details: {
        declaredExtension: cleanExt,
        detectedType,
        detectedMime,
        fileHeaderHex,
      },
    });
  } else if (matchedSig && !matchedSig.mime.includes(cleanExt) && cleanExt.length > 0) {
    // Other noticeable mismatches
    const harmlessTextMismatches = cleanExt === 'txt' || cleanExt === 'json' || cleanExt === 'csv';
    if (!harmlessTextMismatches && !matchedSig.isArchive) {
      if ((imageExts.has(cleanExt) && !matchedSig.mime.startsWith('image/')) ||
          (docExts.has(cleanExt) && !matchedSig.mime.includes('pdf') && !matchedSig.mime.includes('office'))) {
        isMismatch = true;
        detections.push({
          engine: 'MagicBytesEngine',
          category: 'extension_mismatch',
          severity: 'high',
          ruleId: 'MB-002',
          title: 'File Signature Type Mismatch',
          description: `The file extension .${cleanExt} does not match its internal binary magic signature (${detectedType}).`,
          details: { declaredExtension: cleanExt, detectedType, detectedMime },
        });
      }
    }
  }

  return {
    detectedMimeType: detectedMime,
    detectedType,
    fileHeaderHex,
    isExecutable: Boolean(isExecutable),
    isArchive: Boolean(isArchive),
    isScript: Boolean(isScript),
    isMismatch,
    detections,
  };
}
