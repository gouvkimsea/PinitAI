import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { logger } from './logger';

/**
 * Sanitizes a filename to prevent directory traversal and special character exploits.
 */
export function sanitizeFilename(originalName: string): string {
  // Remove path delimiters, null bytes, control characters
  // eslint-disable-next-line no-control-regex
  let clean = path.basename(originalName).replace(/[\0\x00-\x1f\x7f-\x9f]/g, '');
  // Replace slashes or backslashes
  clean = clean.replace(/[/\\?%*:|"<>]/g, '_');
  // Trim spaces and dots at the end
  clean = clean.trim().replace(/^\.+/, '').replace(/\.+$/, '');
  
  if (!clean || clean.length === 0) {
    clean = `unnamed_${Date.now()}`;
  }
  
  // Truncate to safe length
  if (clean.length > 200) {
    const ext = path.extname(clean);
    clean = clean.substring(0, 190) + ext;
  }
  
  return clean;
}

/**
 * Detects dangerous double extensions such as invoice.pdf.exe
 */
export function detectSuspiciousDoubleExtension(filename: string): {
  isDoubleExtension: boolean;
  actualExtension: string;
  disguisedExtension: string;
} {
  const parts = filename.split('.');
  if (parts.length >= 3) {
    const actualExt = parts[parts.length - 1].toLowerCase();
    const disguisedExt = parts[parts.length - 2].toLowerCase();
    
    const executableExts = new Set(['exe', 'scr', 'bat', 'vbs', 'cmd', 'ps1', 'js', 'hta', 'cpl', 'pif']);
    const innocentExts = new Set(['pdf', 'docx', 'xlsx', 'jpg', 'png', 'txt', 'mp3', 'mp4', 'zip']);
    
    if (executableExts.has(actualExt) && innocentExts.has(disguisedExt)) {
      return {
        isDoubleExtension: true,
        actualExtension: actualExt,
        disguisedExtension: disguisedExt,
      };
    }
  }
  
  return {
    isDoubleExtension: false,
    actualExtension: path.extname(filename).replace('.', '').toLowerCase(),
    disguisedExtension: '',
  };
}

/**
 * Safely removes a file from the filesystem.
 */
export async function secureDeleteFile(filePath: string): Promise<boolean> {
  try {
    if (fs.existsSync(filePath)) {
      try {
        const stats = await fs.promises.stat(filePath);
        if (stats.size > 0) {
          const wipeSize = Math.min(stats.size, 4096);
          const zeroBuffer = Buffer.alloc(wipeSize, 0);
          const fd = await fs.promises.open(filePath, 'r+');
          await fd.write(zeroBuffer, 0, wipeSize, 0);
          await fd.close();
        }
      } catch {
        // Fallback directly to unlink
      }
      await fs.promises.unlink(filePath);
      logger.debug('Safely wiped and unlinked temporary file', { filePath });
      return true;
    }
    return false;
  } catch (err) {
    logger.warn('Failed to securely delete temporary file', { filePath, error: (err as Error).message });
    return false;
  }
}

/**
 * Generates a high-entropy random API key.
 */
export function generateApiKey(): string {
  return `pk_${crypto.randomBytes(24).toString('hex')}`;
}

/**
 * Hashes an API key using SHA-256 for secure database storage.
 */
export function hashApiKey(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey.trim()).digest('hex');
}

/**
 * Format bytes into human readable string.
 */
export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}
