import fs from 'fs';
import path from 'path';
import winston from 'winston';
import { config } from '../config';

// Comprehensive set of sensitive keys to redact at all levels of log payloads
const SENSITIVE_KEYS = new Set([
  'password',
  'passwordhash',
  'password_hash',
  'current_password',
  'new_password',
  'token',
  'jwt',
  'access_token',
  'refresh_token',
  'authorization',
  'apikey',
  'api_key',
  'x-api-key',
  'secret',
  'client_secret',
  'cookie',
  'set-cookie',
  'creditcard',
  'credit_card',
  'cardnumber',
  'card_number',
  'cvv',
  'ssn',
  'privatekey',
  'private_key',
]);

/**
 * Recursively redacts sensitive fields and values matching credential patterns.
 */
export function sanitizeLogValue(val: unknown, depth = 0): unknown {
  if (depth > 8) return '[MAX_DEPTH_EXCEEDED]';
  if (val === null || val === undefined) return val;

  if (typeof val === 'string') {
    // Redact Bearer tokens in strings
    if (/^Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/i.test(val.trim())) {
      return 'Bearer [REDACTED_JWT]';
    }
    return val;
  }

  if (Array.isArray(val)) {
    return val.map((item) => sanitizeLogValue(item, depth + 1));
  }

  if (typeof val === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      const normalizedKey = k.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (SENSITIVE_KEYS.has(normalizedKey) || Array.from(SENSITIVE_KEYS).some((sk) => normalizedKey.includes(sk))) {
        sanitized[k] = '[REDACTED]';
      } else {
        sanitized[k] = sanitizeLogValue(v, depth + 1);
      }
    }
    return sanitized;
  }

  return val;
}

const maskSensitiveFormat = winston.format((info) => {
  // Winston info contains symbol keys (e.g. Symbol(message)) and string keys.
  // We sanitize all own string properties except standard winston primitives.
  for (const key of Object.keys(info)) {
    if (key === 'level' || key === 'timestamp') continue;
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (SENSITIVE_KEYS.has(normalized) || Array.from(SENSITIVE_KEYS).some((sk) => normalized.includes(sk))) {
      info[key] = '[REDACTED]';
    } else {
      info[key] = sanitizeLogValue(info[key]);
    }
  }
  return info;
});

const logTransports: winston.transport[] = [
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.printf(({ level, message, timestamp, stack, event_type, ...meta }) => {
        const eventPrefix = event_type ? `[${event_type}] ` : '';
        const metaStr = Object.keys(meta).length > 1 ? ` ${JSON.stringify(meta)}` : '';
        return `[${timestamp}] [${level}]: ${eventPrefix}${stack || message}${metaStr}`;
      })
    ),
  }),
];

// Persistent file transports for production and development (bypassed in test to prevent disk churn)
if (process.env.NODE_ENV !== 'test') {
  try {
    const logDir = config.logDir || path.resolve(process.cwd(), 'logs');
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    logTransports.push(
      new winston.transports.File({
        filename: path.join(logDir, 'app.log'),
        maxsize: 25 * 1024 * 1024, // 25MB
        maxFiles: 5,
        tailable: true,
      }),
      new winston.transports.File({
        filename: path.join(logDir, 'error.log'),
        level: 'error',
        maxsize: 25 * 1024 * 1024,
        maxFiles: 5,
      })
    );
  } catch {
    // If filesystem is read-only, console transport still operates reliably
  }
}

const baseWinstonLogger = winston.createLogger({
  level: config.isProduction ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    maskSensitiveFormat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'pinit-security-service' },
  transports: logTransports,
});

/**
 * Structured Tracking Event Payloads
 */
export interface ApiRequestLogData {
  method: string;
  endpoint: string;
  statusCode: number;
  durationMs: number;
  ipHash?: string | null;
  userId?: string | null;
  contentLength?: number;
}

export interface DetectionFailureLogData {
  scanId: string;
  detectorName: string;
  error: string;
  context?: Record<string, unknown>;
}

export interface AiFailureLogData {
  scanId?: string;
  provider: string;
  error: string;
  fallbackUsed: boolean;
  durationMs?: number;
}

export interface FileProcessingFailureLogData {
  scanId?: string;
  fileName: string;
  error: string;
  stage: string;
  sizeBytes?: number;
}

export interface RateLimitViolationLogData {
  clientKey: string;
  endpoint: string;
  limit: number;
  windowMs: number;
}

export interface AuthFailureLogData {
  reason: string;
  endpoint: string;
  clientIpHash?: string | null;
  userId?: string | null;
}

export interface SuspiciousActivityLogData {
  activityType: string;
  details: Record<string, unknown>;
  clientIpHash?: string | null;
  severity?: 'WARNING' | 'HIGH' | 'CRITICAL';
}

export interface DatabaseErrorLogData {
  operation: string;
  error: string;
  durationMs?: number;
  target?: string;
}

/**
 * AppLogger wraps winston with high-level typed telemetry & audit tracking methods.
 */
class AppLogger {
  private winston: winston.Logger;

  constructor(winstonInstance: winston.Logger) {
    this.winston = winstonInstance;
  }

  info(message: string, meta?: Record<string, unknown>): void {
    this.winston.info(message, meta);
  }

  warn(message: string, meta?: Record<string, unknown>): void {
    this.winston.warn(message, meta);
  }

  error(message: string, meta?: Record<string, unknown>): void {
    this.winston.error(message, meta);
  }

  debug(message: string, meta?: Record<string, unknown>): void {
    this.winston.debug(message, meta);
  }

  // 1. API Requests & Processing Time Tracking
  trackApiRequest(data: ApiRequestLogData): void {
    const isSlow = data.durationMs > 1000;
    const level = isSlow ? 'warn' : 'info';
    const message = `HTTP ${data.method} ${data.endpoint} ${data.statusCode} [${data.durationMs}ms]${isSlow ? ' (SLOW_REQUEST)' : ''}`;

    this.winston.log(level, message, {
      event_type: 'API_REQUEST',
      method: data.method,
      endpoint: data.endpoint,
      statusCode: data.statusCode,
      durationMs: data.durationMs,
      isSlow,
      ipHash: data.ipHash || null,
      userId: data.userId || null,
      contentLength: data.contentLength,
    });
  }

  // 2. Detection Failures Tracking
  trackDetectionFailure(data: DetectionFailureLogData): void {
    this.winston.warn(`Detector '${data.detectorName}' encountered failure during execution`, {
      event_type: 'DETECTION_FAILURE',
      scanId: data.scanId,
      detectorName: data.detectorName,
      error: data.error,
      context: data.context,
    });
  }

  // 3. AI Failures Tracking
  trackAiFailure(data: AiFailureLogData): void {
    this.winston.warn(`AI service failure with provider '${data.provider}'. Fallback used: ${data.fallbackUsed}`, {
      event_type: 'AI_FAILURE',
      scanId: data.scanId,
      provider: data.provider,
      error: data.error,
      fallbackUsed: data.fallbackUsed,
      durationMs: data.durationMs,
    });
  }

  // 4. File-Processing Failures Tracking
  trackFileProcessingFailure(data: FileProcessingFailureLogData): void {
    this.winston.error(`File processing failure in stage '${data.stage}' for file '${data.fileName}'`, {
      event_type: 'FILE_PROCESSING_FAILURE',
      scanId: data.scanId,
      fileName: data.fileName,
      stage: data.stage,
      error: data.error,
      sizeBytes: data.sizeBytes,
    });
  }

  // 5. Rate-Limit Violations Tracking
  trackRateLimitViolation(data: RateLimitViolationLogData): void {
    this.winston.warn(`Rate limit exceeded on endpoint '${data.endpoint}' for client '${data.clientKey}'`, {
      event_type: 'RATE_LIMIT_VIOLATION',
      clientKey: data.clientKey,
      endpoint: data.endpoint,
      limit: data.limit,
      windowMs: data.windowMs,
    });
  }

  // 6. Authentication Failures Tracking
  trackAuthFailure(data: AuthFailureLogData): void {
    this.winston.warn(`Authentication failed on '${data.endpoint}': ${data.reason}`, {
      event_type: 'AUTH_FAILURE',
      reason: data.reason,
      endpoint: data.endpoint,
      clientIpHash: data.clientIpHash || null,
      userId: data.userId || null,
    });
  }

  // 7. Suspicious Activity Tracking
  trackSuspiciousActivity(data: SuspiciousActivityLogData): void {
    const severity = data.severity || 'WARNING';
    const logMethod = severity === 'CRITICAL' ? 'error' : 'warn';

    this.winston[logMethod](`Suspicious activity detected: [${data.activityType}]`, {
      event_type: 'SUSPICIOUS_ACTIVITY',
      activityType: data.activityType,
      severity,
      details: data.details,
      clientIpHash: data.clientIpHash || null,
    });
  }

  // 8. Database Errors Tracking
  trackDatabaseError(data: DatabaseErrorLogData): void {
    this.winston.error(`Database error during operation '${data.operation}'`, {
      event_type: 'DATABASE_ERROR',
      operation: data.operation,
      error: data.error,
      target: data.target,
      durationMs: data.durationMs,
    });
  }

  get raw(): winston.Logger {
    return this.winston;
  }
}

export const logger = new AppLogger(baseWinstonLogger);
