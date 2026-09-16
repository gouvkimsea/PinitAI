import prisma from '../database/client';
import { config } from '../config';
import { logger } from '../utils/logger';

export interface RetentionPurgeResult {
  retentionDays: number;
  cutoffDate: string;
  purgedApiUsageCount: number;
  purgedSecurityEventsCount: number;
  purgedScansCount: number;
}

/**
 * Data Retention & Privacy Lifecycle Worker
 * Enforces GDPR/PDPA compliance by automatically pruning historical usage,
 * security event telemetry, and completed scan artifacts past the configured retention threshold.
 */
export class RetentionWorker {
  private timer: NodeJS.Timeout | null = null;

  /**
   * Executes a database-level purge of records older than the retention cutoff.
   */
  async purgeExpiredData(retentionDays = config.dataRetentionDays): Promise<RetentionPurgeResult> {
    const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
    const infoCutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30-day purge for benign INFO events

    logger.info('Starting data retention purge job', {
      retentionDays,
      cutoffDate: cutoffDate.toISOString(),
    });

    let purgedApiUsageCount = 0;
    let purgedSecurityEventsCount = 0;
    let purgedScansCount = 0;

    try {
      // 1. Purge expired API usage metrics
      const usageResult = await prisma.apiUsage.deleteMany({
        where: { createdAt: { lt: cutoffDate } },
      });
      purgedApiUsageCount = usageResult.count;

      // 2. Purge old security events (> retentionDays, or INFO severity > 30 days)
      const secResult = await prisma.securityEvent.deleteMany({
        where: {
          OR: [
            { createdAt: { lt: cutoffDate } },
            { severity: 'INFO', createdAt: { lt: infoCutoff } },
          ],
        },
      });
      purgedSecurityEventsCount = secResult.count;

      // 3. Purge terminal scans (COMPLETED or FAILED) older than retention period in safe batches of 500
      let hasMoreScans = true;
      const batchSize = 500;
      while (hasMoreScans) {
        const expiredBatch = await prisma.scan.findMany({
          where: {
            createdAt: { lt: cutoffDate },
            status: { in: ['COMPLETED', 'FAILED'] },
          },
          select: { id: true },
          take: batchSize,
        });

        if (expiredBatch.length === 0) {
          hasMoreScans = false;
          break;
        }

        const idsToDelete = expiredBatch.map((s) => s.id);
        const deletedResult = await prisma.scan.deleteMany({
          where: { id: { in: idsToDelete } },
        });

        purgedScansCount += deletedResult.count;

        if (expiredBatch.length < batchSize) {
          hasMoreScans = false;
        } else {
          // Micro-pause between batches to release database locks
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
      }

      logger.info('Data retention purge job completed successfully', {
        purgedApiUsageCount,
        purgedSecurityEventsCount,
        purgedScansCount,
        cutoffDate: cutoffDate.toISOString(),
      });
    } catch (err) {
      logger.error('Data retention purge job encountered an error', {
        error: (err as Error).message,
      });
    }

    return {
      retentionDays,
      cutoffDate: cutoffDate.toISOString(),
      purgedApiUsageCount,
      purgedSecurityEventsCount,
      purgedScansCount,
    };
  }

  /**
   * Starts a daily recurring retention check.
   */
  startScheduledPurge(intervalMs = 24 * 60 * 60 * 1000): void {
    if (this.timer) return;
    // Initial run delayed by 5 minutes after startup to not block initial boot
    setTimeout(() => {
      this.purgeExpiredData().catch(() => {});
    }, 5 * 60 * 1000).unref();

    this.timer = setInterval(() => {
      this.purgeExpiredData().catch(() => {});
    }, intervalMs);
    this.timer.unref();
    logger.info('Automated data retention schedule initialized (daily cycle)');
  }

  stopScheduledPurge(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}

export const retentionWorker = new RetentionWorker();
