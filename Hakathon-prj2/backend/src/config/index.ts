import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const isProduction = process.env.NODE_ENV === 'production';

// Strict secret verification in production to prevent use of known default secrets
const rawJwtSecret = process.env.JWT_SECRET || (isProduction ? '' : 'fallback_default_jwt_secret_change_me_immediately_32chars');
if (isProduction && (!rawJwtSecret || rawJwtSecret.includes('fallback_default') || rawJwtSecret.length < 32)) {
  throw new Error('FATAL SECURITY ERROR: In production, JWT_SECRET must be set via environment variable and be at least 32 characters long.');
}

const parsedCorsOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173,http://localhost:5174')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

export const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isProduction,
  apiPrefix: process.env.API_PREFIX || '/api/v1',
  corsOrigins: parsedCorsOrigins,

  // Database
  databaseUrl: process.env.DATABASE_URL || 'file:./dev.db',
  databaseProvider: process.env.DATABASE_PROVIDER || (process.env.DATABASE_URL?.startsWith('postgres') ? 'postgresql' : 'sqlite'),

  // JWT
  jwtSecret: rawJwtSecret || 'fallback_default_jwt_secret_change_me_immediately_32chars',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '15m',

  // Upload limits
  maxFileSizeBytes: parseInt(process.env.MAX_FILE_SIZE_BYTES || '26214400', 10), // 25MB
  uploadTempDir: path.resolve(process.cwd(), process.env.UPLOAD_TEMP_DIR || './storage/temp'),

  // Logging & Retention
  logDir: process.env.LOG_DIR || (isProduction ? '/app/logs' : path.resolve(process.cwd(), 'logs')),
  dataRetentionDays: parseInt(process.env.DATA_RETENTION_DAYS || '90', 10),

  // Redis / Queue
  redisUrl: process.env.REDIS_URL || '',

  // ClamAV
  clamav: {
    host: process.env.CLAMAV_HOST || 'localhost',
    port: parseInt(process.env.CLAMAV_PORT || '3310', 10),
    timeoutMs: parseInt(process.env.CLAMAV_TIMEOUT_MS || '10000', 10),
  },

  // Threat Intel APIs
  virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY || '',

  // AI Engine
  aiEngineUrl: process.env.AI_ENGINE_URL || 'http://127.0.0.1:8000',
  adminApiKey: process.env.ADMIN_API_KEY || '',

  // Gemini LLM — Explanation Layer
  // Optional: if not set, the explanation engine falls back to the deterministic rules engine
  geminiApiKey: process.env.GEMINI_API_KEY || '',
  geminiModel: process.env.GEMINI_MODEL || 'gemini-2.0-flash',
  geminiTimeoutMs: parseInt(process.env.GEMINI_TIMEOUT_MS || '8000', 10),

  // Rate Limiting & Abuse Protection
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 mins
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '200', 10),
    // Granular endpoint limits
    textScanMax: parseInt(process.env.RATE_LIMIT_TEXT_MAX || '30', 10), // 30 text scans / min
    urlScanMax: parseInt(process.env.RATE_LIMIT_URL_MAX || '20', 10),   // 20 URL scans / min
    fileScanMax: parseInt(process.env.RATE_LIMIT_FILE_MAX || '10', 10), // 10 file scans / min
    aiMax: parseInt(process.env.RATE_LIMIT_AI_MAX || '15', 10),         // 15 AI requests / 15 mins
    reportsMax: parseInt(process.env.RATE_LIMIT_REPORTS_MAX || '10', 10), // 10 reports / 15 mins
    feedbackMax: parseInt(process.env.RATE_LIMIT_FEEDBACK_MAX || '20', 10), // 20 feedback / 15 mins
  },

  // Payload & Content Size Limits
  payloadLimits: {
    maxTextLengthChars: parseInt(process.env.MAX_TEXT_LENGTH_CHARS || '10000', 10), // 10,000 characters
    maxJsonBodyBytes: parseInt(process.env.MAX_JSON_BODY_BYTES || '1048576', 10), // 1MB default json body limit
  },

  // Request & Execution Timeout Limits
  timeouts: {
    requestTimeoutMs: parseInt(process.env.REQUEST_TIMEOUT_MS || '30000', 10), // 30s max for HTTP request
    aiRequestTimeoutMs: parseInt(process.env.AI_REQUEST_TIMEOUT_MS || '10000', 10), // 10s for AI engine
    fileAnalysisTimeoutMs: parseInt(process.env.FILE_ANALYSIS_TIMEOUT_MS || '15000', 10), // 15s for file analysis
  },
};

