import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import multer from 'multer';
import { config } from '../config';

// Ensure upload temporary directory exists
if (!fs.existsSync(config.uploadTempDir)) {
  fs.mkdirSync(config.uploadTempDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, config.uploadTempDir);
  },
  filename: (_req, file, cb) => {
    // Generate secure random filename preserving original extension
    const ext = path.extname(file.originalname).substring(0, 10);
    const randomHex = crypto.randomBytes(16).toString('hex');
    cb(null, `scan_${Date.now()}_${randomHex}${ext}`);
  },
});

export const fileUpload = multer({
  storage,
  limits: {
    fileSize: config.maxFileSizeBytes,
    files: 1, // Single file per scan
  },
  fileFilter: (_req, file, cb) => {
    if (!file.originalname || file.originalname.trim().length === 0) {
      return cb(new Error('Uploaded file must have a valid filename.'));
    }
    cb(null, true);
  },
});
