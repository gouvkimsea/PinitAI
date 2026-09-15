import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import prisma from '../database/client';
import { scanQueue } from '../workers/scanQueue';
import { config } from '../config';
import { sendAnalysisResponse, sendErrorResponse } from '../utils/responseFormatter';

export class FileScanController {
  /**
   * POST /api/v1/files/scan
   * Accepts uploaded file and queues it for background scanning.
   */
  async submitFileScan(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
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

      // Create queued scan in DB
      const scan = await prisma.scan.create({
        data: {
          type: 'FILE',
          target: file.originalname,
          status: 'QUEUED',
          userId: req.user?.id || null,
        },
      });

      // Enqueue job for background processing
      await scanQueue.addJob({
        type: 'FILE',
        scanId: scan.id,
        tempFilePath: file.path,
        originalName: file.originalname,
        mimeType: file.mimetype,
      });

      res.status(202).json({
        success: true,
        scan_id: scan.id,
        status: 'QUEUED',
        message: 'File successfully accepted and queued for security scanning.',
        file_name: file.originalname,
        size_bytes: file.size,
        check_status_url: `${config.apiPrefix}/files/scan/${scan.id}`,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/files/scan/:id
   * Retrieves scan status and full results.
   */
  async getFileScanResult(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);

      const scan = await prisma.scan.findUnique({
        where: { id },
        include: {
          fileRecord: {
            include: { hashes: true },
          },
          scanResult: true,
          detections: true,
        },
      });

      if (!scan || scan.type !== 'FILE') {
        sendErrorResponse(
          res,
          404,
          'SCAN_NOT_FOUND',
          `File scan with ID '${id}' does not exist.`,
          req
        );
        return;
      }

      if (scan.status === 'QUEUED' || scan.status === 'PROCESSING') {
        res.status(200).json({
          success: true,
          scan_id: scan.id,
          status: scan.status,
          created_at: scan.createdAt,
          message: 'Analysis is currently in progress. Poll this endpoint to receive finalized results.',
        });
        return;
      }

      let parsedSafeFactors: string[] = [];
      let parsedRecommendations: string[] = [];
      if (scan.scanResult) {
        try {
          parsedSafeFactors = JSON.parse(scan.scanResult.safeFactors);
          parsedRecommendations = JSON.parse(scan.scanResult.recommendations);
        } catch {
          // ignore parse error
        }
      }

      sendAnalysisResponse(
        res,
        {
          analysis_id: scan.id,
          scan_id: scan.id,
          status: scan.status,
          type: scan.type,
          file_name: scan.fileRecord?.originalName || scan.target,
          threat_level: scan.riskLevel,
          risk_score: scan.riskScore,
          malicious: scan.riskLevel === 'MALICIOUS' || scan.riskLevel === 'HIGH_RISK',
          threat_confidence: scan.threatConfidence,
          confidence: scan.threatConfidence === 'HIGH' ? 85 : 70,
          scan_duration_ms: scan.scanDurationMs,
          created_at: scan.createdAt,
          completed_at: scan.completedAt,
          file_details: scan.fileRecord
            ? {
                original_name: scan.fileRecord.originalName,
                sanitized_name: scan.fileRecord.sanitizedName,
                extension: scan.fileRecord.extension,
                declared_mime: scan.fileRecord.mimeType,
                detected_mime: scan.fileRecord.detectedMimeType,
                size_bytes: scan.fileRecord.sizeBytes,
                hashes: scan.fileRecord.hashes
                  ? {
                      sha256: scan.fileRecord.hashes.sha256,
                      sha1: scan.fileRecord.hashes.sha1,
                      md5: scan.fileRecord.hashes.md5,
                    }
                  : null,
              }
            : null,
          summary: scan.scanResult?.summary,
          engines_breakdown: scan.scanResult
            ? {
                total_engines: scan.scanResult.totalEngines,
                malicious_engines: scan.scanResult.maliciousEngines,
                suspicious_engines: scan.scanResult.suspiciousEngines,
                clean_engines: scan.scanResult.cleanEngines,
              }
            : null,
          detections: scan.detections.map((d) => ({
            engine: d.engine,
            category: d.category,
            severity: d.severity,
            title: d.title,
            description: d.description,
            details: d.details ? JSON.parse(d.details) : undefined,
          })),
          safe_factors: parsedSafeFactors,
          recommendations: parsedRecommendations,
          error_message: scan.errorMessage,
        },
        req
      );
    } catch (err) {
      next(err);
    }
  }
}

export const fileScanController = new FileScanController();
