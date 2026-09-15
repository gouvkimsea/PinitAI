import { createHash } from 'crypto';
import prisma from '../database/client';
import { logger } from './logger';

export type SecurityEventType =
  | 'AUTH_FAILURE'
  | 'AUTH_SUCCESS'
  | 'RATE_LIMIT_EXCEEDED'
  | 'MALICIOUS_UPLOAD'
  | 'SSRF_ATTEMPT'
  | 'API_KEY_REVOKED'
  | 'API_KEY_GENERATED'
  | 'UNAUTHORIZED_ACCESS_ATTEMPT'
  | 'USER_DELETED';

export type SecurityEventSeverity = 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';

export interface LogSecurityEventParams {
  eventType: SecurityEventType;
  severity: SecurityEventSeverity;
  userId?: string | null;
  rawIp?: string | null;
  targetResource?: string | null;
  details?: Record<string, unknown> | null;
}

/**
 * Creates a salted SHA-256 hash of an IP address to preserve privacy while enabling
 * threat correlation and deduplication. Never logs or stores raw IP addresses.
 */
export function hashSecurityIp(rawIp: string): string {
  return createHash('sha256')
    .update(`pinit_security_ip_salt:${rawIp}`)
    .digest('hex');
}

/**
 * Logs a security event to both the structured application logger and the security_events database table.
 * Asynchronous & non-blocking to ensure fast request handling.
 */
export async function logSecurityEvent(params: LogSecurityEventParams): Promise<void> {
  const ipHash = params.rawIp ? hashSecurityIp(params.rawIp) : null;

  logger.info(`[SECURITY_EVENT] ${params.eventType} [${params.severity}]`, {
    eventType: params.eventType,
    severity: params.severity,
    userId: params.userId,
    targetResource: params.targetResource,
    hasIpHash: Boolean(ipHash),
  });

  try {
    await prisma.securityEvent.create({
      data: {
        eventType: params.eventType,
        severity: params.severity,
        userId: params.userId || null,
        ipHash,
        targetResource: params.targetResource ? params.targetResource.slice(0, 255) : null,
        details: params.details ? JSON.stringify(params.details) : null,
      },
    });
  } catch (err) {
    logger.warn('Failed to persist security event to database', {
      eventType: params.eventType,
      error: (err as Error).message,
    });
  }
}
