import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import prisma from '../database/client';
import crypto from 'crypto';
import { MetricsCollector } from '../modules/monitoring/metricsCollector';

interface QueuedApiUsage {
  userId: string | null;
  apiKeyHash: string | null;
  endpoint: string;
  method: string;
  statusCode: number;
  durationMs: number;
  requestCount: number;
  clientIpHash: string | null;
  createdAt: Date;
}

let apiUsageBuffer: QueuedApiUsage[] = [];
let flushTimeout: NodeJS.Timeout | null = null;

async function flushAuditBuffers(): Promise<void> {
  if (flushTimeout) {
    clearTimeout(flushTimeout);
    flushTimeout = null;
  }

  const usagesToFlush = apiUsageBuffer;
  apiUsageBuffer = [];

  if (usagesToFlush.length > 0) {
    try {
      await prisma.apiUsage.createMany({
        data: usagesToFlush,
      });
    } catch {
      // Degrade gracefully if DB writes fail
    }
  }
}

function queueApiUsage(usage: QueuedApiUsage): void {
  apiUsageBuffer.push(usage);
  if (apiUsageBuffer.length >= 25) {
    flushAuditBuffers();
  } else if (!flushTimeout) {
    flushTimeout = setTimeout(flushAuditBuffers, 1500);
  }
}

export async function flushAuditLogsNow(): Promise<void> {
  await flushAuditBuffers();
}

export function auditLogger(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();
  const { method, originalUrl } = req;
  const ip = req.ip || req.socket.remoteAddress || 'unknown';

  res.on('finish', () => {
    const duration = Date.now() - start;
    const statusCode = res.statusCode;
    const user = (req as any).user;
    const clientIpHash = ip && ip !== 'unknown'
      ? crypto.createHash('sha256').update(`pinit_ip_salt:${ip}`).digest('hex')
      : null;

    const isUserDeleted = (req as any).userDeleted || (method === 'DELETE' && originalUrl.includes('/auth/me'));
    const isSyntheticUser = !user?.id || user.id === 'admin-master' || user.id.startsWith('admin-');
    const effectiveUserId = (isUserDeleted || isSyntheticUser) ? null : user.id;

    // 1. Record in real-time metrics collector
    MetricsCollector.getInstance().recordApiRequest(duration, statusCode);

    // 2. Structured API Request Telemetry
    const requestId = (req as any).id || (req as any).requestId || req.headers['x-request-id'] || null;
    logger.trackApiRequest({
      method,
      endpoint: originalUrl,
      statusCode,
      durationMs: duration,
      requestId: typeof requestId === 'string' ? requestId : null,
      ipHash: clientIpHash,
      userId: effectiveUserId,
      contentLength: parseInt(res.get('content-length') || '0', 10) || undefined,
    });

    // 3. Batch-buffered persistence for non-health endpoints to avoid DB write locks
    if (!originalUrl.includes('/health')) {
      const now = new Date();
      const apiKeyHeader = req.headers['x-api-key'] as string | undefined;
      const apiKeyHash = apiKeyHeader ? crypto.createHash('sha256').update(apiKeyHeader.trim()).digest('hex') : null;

      queueApiUsage({
        userId: effectiveUserId,
        apiKeyHash,
        endpoint: originalUrl.split('?')[0].substring(0, 255),
        method,
        statusCode,
        durationMs: duration,
        requestCount: 1,
        clientIpHash,
        createdAt: now,
      });
    }
  });

  next();
}

