import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import prisma from '../database/client';
import { sendAnalysisResponse, sendErrorResponse } from '../utils/responseFormatter';

export class ScanHistoryController {
  /**
   * GET /api/v1/scans
   * Retrieves paginated scan history with optional filtering.
   */
  async listScans(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const page = Math.max(1, parseInt((req.query.page as string) || '1', 10));
      const limit = Math.min(100, Math.max(1, parseInt((req.query.limit as string) || '10', 10)));
      const skip = (page - 1) * limit;

      const typeFilter = req.query.type as string | undefined;
      const statusFilter = req.query.status as string | undefined;
      const riskLevelFilter = req.query.riskLevel as string | undefined;

      const whereClause: Record<string, unknown> = {};

      // Role / User filtering: if regular user, only show their own scans
      if (req.user && req.user.role !== 'admin') {
        whereClause.userId = req.user.id;
      }

      if (typeFilter && ['FILE', 'URL', 'MESSAGE', 'QR'].includes(typeFilter.toUpperCase())) {
        whereClause.type = typeFilter.toUpperCase();
      }

      if (statusFilter) {
        whereClause.status = statusFilter.toUpperCase();
      }

      if (riskLevelFilter) {
        whereClause.riskLevel = riskLevelFilter.toUpperCase();
      }

      const [totalCount, scans] = await Promise.all([
        prisma.scan.count({ where: whereClause }),
        prisma.scan.findMany({
          where: whereClause,
          skip,
          take: limit,
          orderBy: { createdAt: 'desc' },
          include: {
            fileRecord: { select: { originalName: true, sizeBytes: true, mimeType: true } },
            urlScan: { select: { url: true, domain: true } },
            _count: { select: { detections: true } },
          },
        }),
      ]);

      const items = scans.map((s) => ({
        id: s.id,
        type: s.type,
        target: s.target,
        status: s.status,
        threat_level: s.riskLevel,
        risk_score: s.riskScore,
        detection_count: s._count.detections,
        scan_duration_ms: s.scanDurationMs,
        created_at: s.createdAt,
        completed_at: s.completedAt,
        details:
          s.type === 'FILE'
            ? {
                file_name: s.fileRecord?.originalName,
                size_bytes: s.fileRecord?.sizeBytes,
              }
            : {
                url: s.urlScan?.url,
                domain: s.urlScan?.domain,
              },
      }));

      res.status(200).json({
        success: true,
        data: items,
        pagination: {
          total: totalCount,
          page,
          limit,
          total_pages: Math.ceil(totalCount / limit),
        },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/scans/:id
   * Unified lookup for any scan by ID.
   */
  async getScanById(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);

      const scan = await prisma.scan.findUnique({
        where: { id },
        include: {
          fileRecord: { include: { hashes: true } },
          urlScan: true,
          scanResult: true,
          detections: true,
        },
      });

      if (!scan) {
        sendErrorResponse(
          res,
          404,
          'SCAN_NOT_FOUND',
          `Scan with ID '${id}' was not found.`,
          req
        );
        return;
      }

      // Enforce ownership: If scan belongs to an account, only the owner or an admin may view it
      if (scan.userId) {
        const isOwner = req.user && req.user.id === scan.userId;
        const isAdmin = req.user && req.user.role === 'admin';
        if (!isOwner && !isAdmin) {
          sendErrorResponse(
            res,
            403,
            'FORBIDDEN',
            'You do not have permission to access this private analysis record.',
            req
          );
          return;
        }
      }

      let parsedSafeFactors: string[] = [];
      let parsedRecommendations: string[] = [];
      if (scan.scanResult) {
        try {
          parsedSafeFactors = JSON.parse(scan.scanResult.safeFactors);
          parsedRecommendations = JSON.parse(scan.scanResult.recommendations);
        } catch {
          // ignore
        }
      }

      sendAnalysisResponse(
        res,
        {
          analysis_id: scan.id,
          scan_id: scan.id,
          type: scan.type,
          status: scan.status,
          target: scan.target,
          threat_level: scan.riskLevel,
          risk_score: scan.riskScore,
          malicious: scan.riskLevel === 'MALICIOUS' || scan.riskLevel === 'HIGH_RISK',
          threat_confidence: scan.threatConfidence,
          confidence: scan.threatConfidence === 'HIGH' ? 85 : 70,
          scan_duration_ms: scan.scanDurationMs,
          created_at: scan.createdAt,
          completed_at: scan.completedAt,
          summary: scan.scanResult?.summary,
          file_details: scan.fileRecord,
          url_details: scan.urlScan,
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

  /**
   * DELETE /api/v1/scans/:id
   * Deletes a scan record.
   */
  async deleteScan(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);

      const scan = await prisma.scan.findUnique({
        where: { id },
      });

      if (!scan) {
        sendErrorResponse(
          res,
          404,
          'SCAN_NOT_FOUND',
          `Scan with ID '${id}' was not found.`,
          req
        );
        return;
      }

      if (!req.user) {
        sendErrorResponse(
          res,
          401,
          'UNAUTHORIZED',
          'Authentication is required to delete scan records.',
          req
        );
        return;
      }

      // Check ownership unless admin
      const isOwner = scan.userId && scan.userId === req.user.id;
      const isAdmin = req.user.role === 'admin';
      if (!isOwner && !isAdmin) {
        sendErrorResponse(
          res,
          403,
          'FORBIDDEN',
          'You do not have permission to delete this scan record.',
          req
        );
        return;
      }

      await prisma.scan.delete({
        where: { id },
      });

      res.status(200).json({
        success: true,
        message: `Scan '${id}' and associated threat records have been permanently deleted.`,
      });
    } catch (err) {
      next(err);
    }
  }
}

export const scanHistoryController = new ScanHistoryController();
