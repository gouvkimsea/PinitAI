import { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../config';
import { logger } from '../utils/logger';
import { sendErrorResponse } from '../utils/responseFormatter';
import { RedisRateLimitStore } from './redisRateLimitStore';

export const rateLimitStore = config.redisUrl ? new RedisRateLimitStore(config.redisUrl) : undefined;

/**
 * Composite key generator: combines client IP with authenticated user ID / API key.
 * Prevents attackers from rotating IP addresses to bypass rate limits while authenticated.
 */
export function getClientRateLimitKey(req: Request): string {
  const user = (req as any).user;
  if (user?.id) {
    return `user:${user.id}`;
  }
  const apiKeyHeader = req.headers['x-api-key'] as string | undefined;
  if (apiKeyHeader) {
    return `key:${apiKeyHeader.slice(0, 16)}`;
  }
  return req.ip || req.socket.remoteAddress || 'unknown-client';
}

/**
 * Standard API rate limiter
 */
export const standardApiLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  keyGenerator: getClientRateLimitKey,
  store: rateLimitStore,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    logger.trackRateLimitViolation({
      clientKey: getClientRateLimitKey(req),
      endpoint: req.originalUrl || req.url,
      limit: config.rateLimit.maxRequests,
      windowMs: config.rateLimit.windowMs,
    });
    sendErrorResponse(
      res,
      429,
      'RATE_LIMIT_EXCEEDED',
      'Too many requests from this client. Please try again later.',
      req
    );
  },
});

/**
 * Stricter rate limiter for authentication endpoints (prevent brute-force)
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // max 20 login attempts per window
  store: rateLimitStore,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    logger.trackRateLimitViolation({
      clientKey: getClientRateLimitKey(req),
      endpoint: req.originalUrl || req.url,
      limit: 20,
      windowMs: 15 * 60 * 1000,
    });
    sendErrorResponse(
      res,
      429,
      'AUTH_RATE_LIMIT_EXCEEDED',
      'Too many authentication attempts. Please try again in 15 minutes.',
      req
    );
  },
});

/**
 * Scan submission rate limiter
 */
export const scanSubmissionLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // max 30 scan submissions per minute per IP
  store: rateLimitStore,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    sendErrorResponse(
      res,
      429,
      'SCAN_RATE_LIMIT_EXCEEDED',
      'Scan submission rate limit reached. Please wait before submitting more targets.',
      req
    );
  },
});

/**
 * Feedback submission rate limiter (layer 1 — express-rate-limit).
 */
export const feedbackLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // max 20 feedback submissions per 15 minutes per IP
  store: rateLimitStore,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  handler: (req: Request, res: Response) => {
    sendErrorResponse(
      res,
      429,
      'FEEDBACK_RATE_LIMIT_EXCEEDED',
      'Too many feedback submissions from this client. Please wait 15 minutes before submitting more feedback.',
      req
    );
  },
});
