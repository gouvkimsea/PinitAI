import fs from 'fs';
import path from 'path';
import { calculateFileHashes } from '../../scanners/hash/hashScanner';
import { analyzeMagicBytes } from '../../scanners/file/magicBytes';
import { analyzeFileStatically } from '../../scanners/file/staticAnalyzer';
import { scanWithClamAV } from '../../scanners/antivirus/clamavScanner';
import { threatIntel } from '../../scanners/threatIntel/threatIntelProvider';
import { sanitizeFilename } from '../../utils/helpers';
import { DetectionItem } from '../../types';
import { logger } from '../../utils/logger';

export interface ComprehensiveFileResult {
  fileName: string;
  sanitizedName: string;
  extension: string;
  sizeBytes: number;
  mimeType: string;
  detectedMimeType: string;
  isMimeMismatch: boolean;
  hashes: {
    sha256: string;
    sha1: string;
    md5: string;
  };
  detections: DetectionItem[];
  enginesEvaluated: string[];
}

export class FileAnalyzer {
  /**
   * Performs complete multi-engine analysis on a local file:
   * 1. Cryptographic hashing (SHA-256, SHA-1, MD5)
   * 2. Magic byte file signature verification
   * 3. Static code/macro/executable inspection
   * 4. Antivirus signature engine (ClamAV)
   * 5. Threat intelligence hash lookup
   */
  async analyze(filePath: string, originalName: string, mimeType: string): Promise<ComprehensiveFileResult> {
    logger.info('Performing modular file analysis', { originalName });

    const stats = await fs.promises.stat(filePath);
    const sizeBytes = stats.size;
    const sanitizedName = sanitizeFilename(originalName);
    const extension = path.extname(sanitizedName).replace('.', '').toLowerCase();

    // 1. Compute Hashes
    const hashes = await calculateFileHashes(filePath);

    // 2. Inspect Magic Bytes
    const magicResult = await analyzeMagicBytes(filePath, extension, mimeType);

    // 3. Query Threat Intelligence by Hash
    const hashIntel = await threatIntel.checkHash(hashes.sha256);

    // 4. Static Pattern & Heuristics
    const staticResult = await analyzeFileStatically(filePath, sanitizedName, sizeBytes);

    // 5. Antivirus Scan (ClamAV / Simulated fallback)
    const avResult = await scanWithClamAV(filePath);

    const detections: DetectionItem[] = [
      ...magicResult.detections,
      ...staticResult.detections,
      ...avResult.detections,
    ];

    if (hashIntel && hashIntel.detections) {
      detections.push(...hashIntel.detections);
    }

    const enginesEvaluated = ['HashCalculation', 'MagicBytesEngine', 'StaticAnalyzer', avResult.engine];
    if (hashIntel) {
      enginesEvaluated.push(hashIntel.provider);
    }

    return {
      fileName: originalName,
      sanitizedName,
      extension,
      sizeBytes,
      mimeType,
      detectedMimeType: magicResult.detectedMimeType,
      isMimeMismatch: magicResult.isMismatch,
      hashes,
      detections,
      enginesEvaluated,
    };
  }
}

export const fileAnalyzer = new FileAnalyzer();
