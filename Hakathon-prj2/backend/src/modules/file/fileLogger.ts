import path from 'path';
import crypto from 'crypto';
import { logger } from '../../utils/logger';

export class SecureFileLogger {
  /**
   * Hashes client IP for audit traceability without storing raw identifiable IP.
   */
  public static anonymizeIp(ip?: string): string {
    if (!ip) return 'anonymous';
    return crypto.createHash('sha256').update(ip).digest('hex').substring(0, 12);
  }

  /**
   * Safely logs upload receipt event without logging raw file contents or sensitive paths.
   */
  public static logUploadReceived(params: {
    quarantineId: string;
    sanitizedName: string;
    sizeBytes: number;
    declaredMime: string;
    clientIp?: string;
    userId?: string | null;
  }): void {
    logger.info('File upload quarantined for security inspection', {
      event: 'FILE_UPLOAD_RECEIVED',
      quarantineId: params.quarantineId,
      fileName: params.sanitizedName,
      sizeBytes: params.sizeBytes,
      declaredMime: params.declaredMime,
      user: params.userId ? 'authenticated' : 'anonymous',
      clientHash: this.anonymizeIp(params.clientIp),
    });
  }

  /**
   * Logs completed security analysis audit record.
   */
  public static logAnalysisCompleted(params: {
    quarantineId: string;
    sanitizedName: string;
    sha256: string;
    fileType: string;
    riskScore: number;
    classification: string;
    indicatorsCount: number;
    durationMs: number;
  }): void {
    logger.info('Secure file analysis finished', {
      event: 'FILE_ANALYSIS_COMPLETED',
      quarantineId: params.quarantineId,
      fileName: params.sanitizedName,
      sha256: params.sha256,
      fileType: params.fileType,
      riskScore: params.riskScore,
      classification: params.classification,
      indicatorsCount: params.indicatorsCount,
      durationMs: params.durationMs,
    });
  }

  /**
   * Logs security warnings or anomalies detected during file processing.
   */
  public static logSecurityWarning(params: {
    quarantineId?: string;
    fileName: string;
    warning: string;
    details?: Record<string, unknown>;
  }): void {
    logger.warn('File security anomaly detected', {
      event: 'FILE_SECURITY_ANOMALY',
      quarantineId: params.quarantineId || 'n/a',
      fileName: params.fileName,
      warning: params.warning,
      details: params.details,
    });
  }

  /**
   * Logs safe quarantine deletion/cleanup event.
   */
  public static logCleanup(quarantinePath: string): void {
    logger.debug('Quarantine storage cleaned up', {
      event: 'FILE_QUARANTINE_CLEANED',
      quarantineFile: path.basename(quarantinePath),
    });
  }
}
