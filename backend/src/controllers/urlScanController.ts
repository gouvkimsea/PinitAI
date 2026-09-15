import { Response, NextFunction } from 'express';
import { z } from 'zod';
import { AuthenticatedRequest } from '../middleware/auth';
import prisma from '../database/client';
import { scanQueue } from '../workers/scanQueue';
import { config } from '../config';
import { sendAnalysisResponse, sendErrorResponse } from '../utils/responseFormatter';

import { isValidHttpUrl } from '../validation/analyzeSchemas';

const SubmitUrlSchema = z.object({
  url: z
    .string({ required_error: 'URL is required.' })
    .min(3, 'URL must contain at least 3 characters.')
    .max(2048, 'URL exceeds maximum permitted length of 2048 characters.')
    .refine((val) => isValidHttpUrl(val), 'Invalid URL format. Must be an http or https address.'),
});

export class UrlScanController {
  /**
   * POST /api/v1/urls/scan
   * Submits a URL for security analysis.
   */
  async submitUrlScan(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const validated = SubmitUrlSchema.parse(req.body);
      const targetUrl = validated.url.trim();

      const scan = await prisma.scan.create({
        data: {
          type: 'URL',
          target: targetUrl,
          status: 'QUEUED',
          userId: req.user?.id || null,
        },
      });

      await scanQueue.addJob({
        type: 'URL',
        scanId: scan.id,
        url: targetUrl,
      });

      res.status(202).json({
        success: true,
        scan_id: scan.id,
        status: 'QUEUED',
        message: 'URL successfully submitted and enqueued for security analysis.',
        url: targetUrl,
        check_status_url: `${config.apiPrefix}/urls/scan/${scan.id}`,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/urls/scan/:id
   * Retrieves URL scan status and full results.
   */
  async getUrlScanResult(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);

      const scan = await prisma.scan.findUnique({
        where: { id },
        include: {
          urlScan: true,
          scanResult: true,
          detections: true,
        },
      });

      if (!scan || scan.type !== 'URL') {
        sendErrorResponse(
          res,
          404,
          'SCAN_NOT_FOUND',
          `URL scan with ID '${id}' was not found.`,
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
          message: 'URL analysis in progress. Please poll again shortly.',
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
          url: scan.urlScan?.url || scan.target,
          normalized_url: scan.urlScan?.normalizedUrl,
          domain: scan.urlScan?.domain,
          ip_address: scan.urlScan?.ipAddress,
          is_https: scan.urlScan?.isHttps,
          has_redirects: scan.urlScan?.hasRedirects,
          redirect_count: scan.urlScan?.redirectCount,
          threat_level: scan.riskLevel,
          risk_score: scan.riskScore,
          malicious: scan.riskLevel === 'MALICIOUS' || scan.riskLevel === 'HIGH_RISK',
          threat_confidence: scan.threatConfidence,
          confidence: scan.threatConfidence === 'HIGH' ? 85 : 70,
          scan_duration_ms: scan.scanDurationMs,
          created_at: scan.createdAt,
          completed_at: scan.completedAt,
          summary: scan.scanResult?.summary,
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

export const urlScanController = new UrlScanController();
