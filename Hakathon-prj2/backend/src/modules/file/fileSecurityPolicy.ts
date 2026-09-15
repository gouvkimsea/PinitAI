import path from 'path';
import { config } from '../../config';
import { FileValidationResult } from './types';

export const FILE_SECURITY_POLICY = {
  // Size limits
  MAX_FILE_SIZE_BYTES: config.maxFileSizeBytes || 26_214_400, // 25 MB
  MIN_FILE_SIZE_BYTES: 1, // 0-byte files rejected

  // Resource limits
  MAX_INSPECTION_BUFFER_BYTES: 2 * 1024 * 1024, // 2 MB max buffer for static heuristic regex inspection
  MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES: 100 * 1024 * 1024, // 100 MB zip bomb ceiling
  MAX_ARCHIVE_COMPRESSION_RATIO: 100, // 100:1 ratio zip bomb alert
  MAX_ARCHIVE_ENTRY_COUNT: 500,

  // Processing timeouts
  PROCESSING_TIMEOUT_MS: 15_000, // 15 seconds circuit breaker for total analysis

  // Dangerous execution extensions
  DANGEROUS_EXTENSIONS: new Set([
    'exe', 'scr', 'bat', 'cmd', 'vbs', 'ps1', 'js', 'hta', 'cpl', 'pif',
    'reg', 'wsf', 'jar', 'msi', 'dll', 'com', 'sys', 'iso', 'vhd', 'dmg'
  ]),

  // Supported standard document & media extensions
  SAFE_DOCUMENT_EXTENSIONS: new Set([
    'pdf', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt', 'odt', 'rtf',
    'txt', 'csv', 'json', 'xml'
  ]),

  SAFE_MEDIA_EXTENSIONS: new Set([
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'tiff'
  ]),

  SAFE_ARCHIVE_EXTENSIONS: new Set([
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2'
  ]),
};

/**
 * Strict filename sanitizer protecting against path traversal, control characters,
 * null byte poisoning, and shell injection.
 */
export function sanitizeUploadFilename(originalName: string): string {
  if (!originalName || typeof originalName !== 'string') {
    return `upload_${Date.now()}.bin`;
  }

  // 1. Remove path delimiters and directory traversal
  let clean = path.basename(originalName);

  // 2. Strip null bytes, control chars, and unicode directional override marks
  // eslint-disable-next-line no-control-regex
  clean = clean.replace(/[\0\x00-\x1f\x7f-\x9f\u200E\u200F\u202A-\u202E]/g, '');

  // 3. Replace dangerous shell and file system metacharacters
  clean = clean.replace(/[/\\?%*:|"<>;&$`()!#~]/g, '_');

  // 4. Strip leading/trailing dots and spaces
  clean = clean.trim().replace(/^\.+/, '').replace(/\.+$/, '');

  if (!clean || clean.length === 0) {
    clean = `upload_${Date.now()}.bin`;
  }

  // 5. Length bounding while preserving extension
  if (clean.length > 200) {
    const ext = path.extname(clean);
    clean = clean.substring(0, 190) + ext;
  }

  return clean;
}

/**
 * Detects deceptive double extensions designed to trick users into executing binaries.
 * Example: invoice.pdf.exe, report.docx.vbs, image.jpg.scr
 */
export function inspectDoubleExtension(filename: string): {
  isDoubleExtension: boolean;
  actualExtension: string;
  disguisedExtension: string;
} {
  const parts = filename.split('.');
  if (parts.length >= 3) {
    const actualExt = parts[parts.length - 1].toLowerCase();
    const disguisedExt = parts[parts.length - 2].toLowerCase();

    if (
      FILE_SECURITY_POLICY.DANGEROUS_EXTENSIONS.has(actualExt) &&
      (FILE_SECURITY_POLICY.SAFE_DOCUMENT_EXTENSIONS.has(disguisedExt) ||
        FILE_SECURITY_POLICY.SAFE_MEDIA_EXTENSIONS.has(disguisedExt))
    ) {
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
 * Validates file upload metadata before or immediately upon disk receipt.
 */
export function validateFileUpload(file: {
  originalname?: string;
  size?: number;
  mimetype?: string;
}): FileValidationResult {
  const rawName = file.originalname || '';
  const fileSize = typeof file.size === 'number' ? file.size : 0;
  const declaredMime = (file.mimetype || 'application/octet-stream').toLowerCase();

  // 1. Validate size
  if (fileSize < FILE_SECURITY_POLICY.MIN_FILE_SIZE_BYTES) {
    return {
      valid: false,
      error: {
        code: 'FILE_EMPTY',
        message: 'Uploaded file is empty (0 bytes). Upload a valid file for analysis.',
        httpStatus: 400,
      },
      sanitizedName: sanitizeUploadFilename(rawName),
      extension: '',
      declaredMime,
      fileSize,
    };
  }

  if (fileSize > FILE_SECURITY_POLICY.MAX_FILE_SIZE_BYTES) {
    return {
      valid: false,
      error: {
        code: 'FILE_TOO_LARGE',
        message: `Uploaded file exceeds maximum allowed limit of ${(FILE_SECURITY_POLICY.MAX_FILE_SIZE_BYTES / (1024 * 1024)).toFixed(0)}MB.`,
        httpStatus: 413,
      },
      sanitizedName: sanitizeUploadFilename(rawName),
      extension: '',
      declaredMime,
      fileSize,
    };
  }

  // 2. Validate and sanitize filename
  const sanitizedName = sanitizeUploadFilename(rawName);
  const extension = path.extname(sanitizedName).replace('.', '').toLowerCase();

  return {
    valid: true,
    sanitizedName,
    extension,
    declaredMime,
    fileSize,
  };
}
