import { Response, NextFunction } from 'express';
import { z } from 'zod';
import prisma from '../database/client';
import { AuthenticatedRequest } from '../middleware/auth';
import { logger } from '../utils/logger';

const ReportSchema = z.object({
  scamType: z.string().min(1).max(50),
  target: z.string().max(2000).optional(),
  description: z.string().min(5, 'Description must be at least 5 characters long.').max(5000),
});

export class ReportController {
  /**
   * POST /api/v1/reports
   * Submits a user scam or malicious threat report.
   */
  async submitReport(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = ReportSchema.parse(req.body);

      const report = await prisma.scamReport.create({
        data: {
          scamType: parsed.scamType.toLowerCase(),
          target: parsed.target ? parsed.target.trim() : null,
          description: parsed.description.trim(),
          userId: req.user?.id || null,
          status: 'PENDING',
        },
      });

      logger.info('New community scam report submitted', {
        reportId: report.id,
        scamType: report.scamType,
        userId: report.userId,
      });

      res.status(201).json({
        success: true,
        message: 'Scam report submitted successfully and queued for intelligence review.',
        report_id: report.id,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/reports
   * Retrieves scam reports (Admin / Analyst restricted).
   */
  async listReports(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string, 10) || 20));
      const skip = (page - 1) * limit;

      const [total, reports] = await Promise.all([
        prisma.scamReport.count(),
        prisma.scamReport.findMany({
          skip,
          take: limit,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            scamType: true,
            target: true,
            description: true,
            status: true,
            createdAt: true,
            user: {
              select: { id: true, email: true },
            },
          },
        }),
      ]);

      res.status(200).json({
        success: true,
        data: reports.map((r) => ({
          id: r.id,
          scam_type: r.scamType,
          target: r.target,
          description: r.description,
          status: r.status,
          user: r.user,
          created_at: r.createdAt,
        })),
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.ceil(total / limit),
        },
      });
    } catch (err) {
      next(err);
    }
  }
}

export const reportController = new ReportController();
