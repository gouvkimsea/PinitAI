import path from 'path';
import multer from 'multer';
import { Request, Response, NextFunction } from 'express';
import { quarantineStorage } from '../modules/file/quarantineStorage';
import {
  FILE_SECURITY_POLICY,
  sanitizeUploadFilename,
} from '../modules/file/fileSecurityPolicy';
import { SecureFileLogger } from '../modules/file/fileLogger';
import { AuthenticatedRequest } from './auth';
import { logger } from '../utils/logger';
import { sendErrorResponse } from '../utils/responseFormatter';

// Ensure quarantine storage directory exists
quarantineStorage.ensureQuarantineDir();

const quarantineMulterStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, quarantineStorage.quarantineDir);
  },
  filename: (_req, file, cb) => {
    const sanitized = sanitizeUploadFilename(file.originalname);
    const ext = path.extname(sanitized).replace('.', '').toLowerCase();
    const { quarantinePath } = quarantineStorage.generateQuarantinePath(ext);
    cb(null, path.basename(quarantinePath));
  },
});

export const secureMulterUpload = multer({
  storage: quarantineMulterStorage,
  limits: {
    fileSize: FILE_SECURITY_POLICY.MAX_FILE_SIZE_BYTES,
    files: 1,
  },
  fileFilter: (_req, file, cb) => {
    if (!file.originalname || file.originalname.trim().length === 0) {
      return cb(new Error('Uploaded file must have a valid filename.'));
    }
    cb(null, true);
  },
});

/**
 * Express middleware that enforces pre-analysis file security checks:
 * 1. Checks for file presence.
 * 2. Checks for empty (0-byte) files.
 * 3. Applies 0o600 non-executable file permissions.
 * 4. Sanitizes filename.
 * 5. Logs audit event securely.
 */
export async function enforceFileSecurity(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  if (!req.file) {
    sendErrorResponse(
      res,
      400,
      'FILE_REQUIRED',
      'No file was uploaded in request. Send multipart/form-data with field name "file".',
      req
    );
    return;
  }

  const file = req.file;

  // 1. Enforce minimum file size (prevent zero-byte payload DOS)
  if (file.size < FILE_SECURITY_POLICY.MIN_FILE_SIZE_BYTES) {
    // Immediately erase empty file from quarantine
    await quarantineStorage.secureDelete(file.path);
    sendErrorResponse(
      res,
      400,
      'FILE_EMPTY',
      'Uploaded file is empty (0 bytes). Provide a valid file for analysis.',
      req
    );
    return;
  }

  // 2. Restrict permissions to owner read/write only (non-executable)
  await quarantineStorage.restrictPermissions(file.path);

  // 3. Sanitize filename and detect path traversal attempts
  if (file.originalname && (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\'))) {
    logger.trackSuspiciousActivity({
      activityType: 'PATH_TRAVERSAL_ATTEMPT',
      severity: 'HIGH',
      details: { rawFilename: file.originalname },
    });
  }

  const sanitizedName = sanitizeUploadFilename(file.originalname);
  const quarantineId = path.basename(file.path, path.extname(file.path));

  // 4. Secure logging
  SecureFileLogger.logUploadReceived({
    quarantineId,
    sanitizedName,
    sizeBytes: file.size,
    declaredMime: file.mimetype,
    clientIp: req.ip,
    userId: req.user?.id,
  });

  next();
}

/**
 * Safe error handling wrapper for Multer upload errors (e.g. file size exceeded).
 */
export function handleUploadErrors(
  err: any,
  _req: Request,
  res: Response,
  next: NextFunction
): void {
  if (err instanceof multer.MulterError) {
    logger.trackFileProcessingFailure({
      fileName: _req.file?.originalname || 'upload_payload',
      stage: 'upload_stream',
      error: err.code === 'LIMIT_FILE_SIZE' ? 'FILE_TOO_LARGE' : err.message,
      sizeBytes: _req.file?.size,
    });

    if (err.code === 'LIMIT_FILE_SIZE') {
      sendErrorResponse(
        res,
        413,
        'FILE_TOO_LARGE',
        `Uploaded file exceeds maximum limit of ${(FILE_SECURITY_POLICY.MAX_FILE_SIZE_BYTES / (1024 * 1024)).toFixed(0)}MB.`,
        _req
      );
      return;
    }
    sendErrorResponse(
      res,
      400,
      'UPLOAD_ERROR',
      err.message,
      _req
    );
    return;
  }
  next(err);
}
