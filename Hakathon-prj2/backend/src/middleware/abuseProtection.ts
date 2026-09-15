import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import prisma from '../database/client';
import { config } from '../config';
import { logger } from '../utils/logger';
import { getClientRateLimitKey, rateLimitStore } from './rateLimiter';
import { sendErrorResponse } from '../utils/responseFormatter';

/**
 * Asynchronously logs a security event to the database and structured logger.
 * Salted IP hashing guarantees zero raw PII storage while enabling forensic correlation.
 */
export async function logAbuseSecurityEvent(options: {
  req: Request;
  eventType: 'RATE_LIMIT_EXCEEDED' | 'PAYLOAD_TOO_LARGE' | 'TIMEOUT_BREACH' | 'ABUSIVE_REQUEST';
  severity?: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  details?: Record<string, unknown>;
}): Promise<void> {
  const { req, eventType, severity = 'WARNING', details = {} } = options;
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const ipHash = ip && ip !== 'unknown'
    ? crypto.createHash('sha256').update(`pinit_ip_salt:${ip}`).digest('hex')
    : null;
  const userId = (req as any).user?.id || null;
  const endpoint = req.originalUrl || req.url;

  logger.warn(`Security event triggered: [${eventType}] on ${req.method} ${endpoint}`, {
    eventType,
    severity,
    ipHash: ipHash?.slice(0, 12),
    userId,
    details,
  });

  try {
    await prisma.securityEvent.create({
      data: {
        userId,
        eventType,
        severity,
        ipHash,
        targetResource: endpoint.substring(0, 255),
        details: JSON.stringify({
          ...details,
          method: req.method,
          userAgent: req.get('user-agent')?.substring(0, 200),
          timestamp: new Date().toISOString(),
        }),
      },
    });
  } catch (err) {
    logger.warn('Failed to record security event in database', { error: (err as Error).message });
  }
}

/**
 * Factory creating rate limiters with automatic SecurityEvent logging upon breach.
 */
function createAbuseProtectedLimiter(options: {
  windowMs: number;
  max: number;
  code: string;
  message: string;
  endpointName: string;
}) {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    keyGenerator: getClientRateLimitKey,
    store: rateLimitStore,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req: Request, res: Response) => {
      // Structured rate-limit violation telemetry
      logger.trackRateLimitViolation({
        clientKey: getClientRateLimitKey(req),
        endpoint: options.endpointName,
        limit: options.max,
        windowMs: options.windowMs,
      });

      // Fire-and-forget abuse logging
      logAbuseSecurityEvent({
        req,
        eventType: 'RATE_LIMIT_EXCEEDED',
        severity: 'WARNING',
        details: {
          limitCode: options.code,
          endpoint: options.endpointName,
          windowMs: options.windowMs,
          max: options.max,
        },
      });

      sendErrorResponse(
        res,
        429,
        options.code,
        options.message,
        req,
        { retryAfterSeconds: Math.ceil(options.windowMs / 1000) }
      );
    },
  });
}

// 1. Text Analysis Limiter (expensive NLP & linguistic heuristics)
export const textScanLimiter = createAbuseProtectedLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: config.rateLimit.textScanMax,
  code: 'TEXT_SCAN_RATE_LIMIT_EXCEEDED',
  message: `Text analysis limit reached (max ${config.rateLimit.textScanMax}/min). Please wait before submitting more messages.`,
  endpointName: 'text-analysis',
});

// 2. URL Analysis Limiter (network probes, DNS resolution, SSRF inspection)
export const urlScanLimiter = createAbuseProtectedLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: config.rateLimit.urlScanMax,
  code: 'URL_SCAN_RATE_LIMIT_EXCEEDED',
  message: `URL analysis limit reached (max ${config.rateLimit.urlScanMax}/min). Please wait before scanning more URLs.`,
  endpointName: 'url-analysis',
});

// 3. File Analysis Limiter (disk I/O, hash extraction, ClamAV antivirus)
export const fileScanLimiter = createAbuseProtectedLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: config.rateLimit.fileScanMax,
  code: 'FILE_SCAN_RATE_LIMIT_EXCEEDED',
  message: `File analysis limit reached (max ${config.rateLimit.fileScanMax}/min). Please wait before uploading more files.`,
  endpointName: 'file-analysis',
});

// 4. AI Explanation & Gateway Limiter (Gemini LLM tokens, Python FastAPI proxy)
export const aiLimiter = createAbuseProtectedLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: config.rateLimit.aiMax,
  code: 'AI_RATE_LIMIT_EXCEEDED',
  message: `AI request limit reached (max ${config.rateLimit.aiMax} per 15 mins). Please wait before requesting additional AI explanations.`,
  endpointName: 'ai-explanation',
});

// 5. Community Reports Limiter (database write prevention against spam)
export const reportsLimiter = createAbuseProtectedLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: config.rateLimit.reportsMax,
  code: 'REPORT_RATE_LIMIT_EXCEEDED',
  message: `Community report submission limit reached (max ${config.rateLimit.reportsMax} per 15 mins). Thank you for your contributions, please wait before submitting more.`,
  endpointName: 'community-reports',
});

// 6. Feedback Limiter
export const feedbackLimiter = createAbuseProtectedLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: config.rateLimit.feedbackMax,
  code: 'FEEDBACK_RATE_LIMIT_EXCEEDED',
  message: `Feedback submission limit reached (max ${config.rateLimit.feedbackMax} per 15 mins). Please try again later.`,
  endpointName: 'feedback',
});

/**
 * Middleware: Enforces maximum string length on text payloads to prevent ReDoS / memory exhaustion
 */
export function enforceTextPayloadLimit(req: Request, res: Response, next: NextFunction): void {
  const body = req.body;
  if (!body) return next();

  const textContent = body.content || body.text || body.raw_text;
  if (typeof textContent === 'string' && textContent.length > config.payloadLimits.maxTextLengthChars) {
    logAbuseSecurityEvent({
      req,
      eventType: 'PAYLOAD_TOO_LARGE',
      severity: 'WARNING',
      details: {
        providedLength: textContent.length,
        maximumAllowed: config.payloadLimits.maxTextLengthChars,
      },
    });

    sendErrorResponse(
      res,
      413,
      'PAYLOAD_TOO_LARGE',
      `Content length (${textContent.length} chars) exceeds the maximum allowed limit of ${config.payloadLimits.maxTextLengthChars} characters.`,
      req
    );
    return;
  }

  next();
}
