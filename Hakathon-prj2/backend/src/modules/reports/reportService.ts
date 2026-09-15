import prisma from '../../database/client';
import { logger } from '../../utils/logger';

export interface CreateReportDTO {
  scamType: string;
  target?: string;
  description: string;
  userId?: string | null;
}

export interface ListReportsQuery {
  page?: number;
  limit?: number;
}

export class ReportService {
  /**
   * Creates a new community threat / scam report
   */
  async createReport(dto: CreateReportDTO) {
    const target = dto.target ? dto.target.trim() : null;
    const targetHash = target
      ? require('crypto').createHash('sha256').update(target.toLowerCase()).digest('hex')
      : null;

    const report = await prisma.scamReport.create({
      data: {
        scamType: dto.scamType.toLowerCase().trim(),
        target,
        targetHash,
        description: dto.description.trim(),
        userId: dto.userId || null,
        status: 'PENDING',
      },
    });

    logger.info('Community scam report stored', {
      reportId: report.id,
      scamType: report.scamType,
      userId: report.userId,
    });

    return report;
  }

  /**
   * Lists paginated scam reports with author details
   */
  async listReports(query: ListReportsQuery) {
    const page = Math.max(1, query.page || 1);
    const limit = Math.min(100, Math.max(1, query.limit || 20));
    const skip = (page - 1) * limit;

    const [total, reports] = await Promise.all([
      prisma.scamReport.count(),
      prisma.scamReport.findMany({
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          user: {
            select: { id: true, email: true },
          },
        },
      }),
    ]);

    return {
      reports,
      pagination: {
        page,
        limit,
        total,
        total_pages: Math.ceil(total / limit),
      },
    };
  }
}

export const reportService = new ReportService();
