import { createHash } from 'crypto';
import prisma from '../../database/client';
import { logger } from '../../utils/logger';

export interface CreateFeedbackDTO {
  analysisId: string;
  userId?: string | null;
  rawIp?: string | null;
  feedbackType: 'correct_detection' | 'incorrect_detection' | 'report_scam' | 'not_sure';
  reportedCategory?: string | null;
  explanation?: string | null;
  targetSnippet?: string | null;
  riskScoreAtTime?: number | null;
}

export interface FeedbackRecord {
  id: string;
  analysisId: string;
  userId: string | null;
  feedbackType: string;
  reportedCategory: string | null;
  explanation: string | null;
  targetSnippet: string | null;
  riskScoreAtTime: number | null;
  isReviewed: boolean;
  reviewedBy: string | null;
  reviewNote: string | null;
  createdAt: Date;
}

export interface FeedbackListOptions {
  feedbackType?: string;
  isReviewed?: boolean;
  analysisId?: string;
  page?: number;
  pageSize?: number;
}

/**
 * One-way hash of the IP address for duplicate detection.
 * Raw IPs are never stored in the database.
 */
export function hashIp(rawIp: string): string {
  return createHash('sha256')
    .update(`scamcheck_feedback_ip_salt:${rawIp}`)
    .digest('hex');
}

export class FeedbackRepository {
  /**
   * Create a new AnalysisFeedback record.
   */
  async create(dto: CreateFeedbackDTO): Promise<FeedbackRecord> {
    const ipHash = dto.rawIp ? hashIp(dto.rawIp) : null;

    const record = await prisma.analysisFeedback.create({
      data: {
        analysisId: dto.analysisId,
        userId: dto.userId ?? null,
        ipHash,
        feedbackType: dto.feedbackType,
        reportedCategory: dto.reportedCategory ?? null,
        explanation: dto.explanation ?? null,
        targetSnippet: dto.targetSnippet ?? null,
        riskScoreAtTime: dto.riskScoreAtTime ?? null,
      },
    });

    logger.info('AnalysisFeedback record created', {
      id: record.id,
      analysisId: record.analysisId,
      feedbackType: record.feedbackType,
      hasUserId: Boolean(record.userId),
      hasIpHash: Boolean(ipHash),
    });

    return record;
  }

  /**
   * Check for duplicate feedback: same analysisId + same ipHash submitted within windowMs.
   * Returns the duplicate record if found, null otherwise.
   *
   * Security: prevents feedback bombing a single analysis.
   */
  async findDuplicate(
    analysisId: string,
    rawIp: string | null | undefined,
    userId: string | null | undefined,
    windowMs: number = 24 * 60 * 60 * 1000 // 24 hours default
  ): Promise<FeedbackRecord | null> {
    const since = new Date(Date.now() - windowMs);
    const ipHash = rawIp ? hashIp(rawIp) : null;

    // Check by userId first (most reliable), then by IP hash
    if (userId) {
      const byUser = await prisma.analysisFeedback.findFirst({
        where: {
          analysisId,
          userId,
          createdAt: { gte: since },
        },
        orderBy: { createdAt: 'desc' },
      });
      if (byUser) return byUser;
    }

    if (ipHash) {
      const byIp = await prisma.analysisFeedback.findFirst({
        where: {
          analysisId,
          ipHash,
          createdAt: { gte: since },
        },
        orderBy: { createdAt: 'desc' },
      });
      if (byIp) return byIp;
    }

    return null;
  }

  /**
   * Count recent feedback submissions from an IP within the window.
   * Used as DB-level rate limiting (layer 2, after express-rate-limit).
   */
  async countRecentByIp(rawIp: string, windowMs: number = 15 * 60 * 1000): Promise<number> {
    const since = new Date(Date.now() - windowMs);
    const ipHash = hashIp(rawIp);

    return prisma.analysisFeedback.count({
      where: {
        ipHash,
        createdAt: { gte: since },
      },
    });
  }

  /**
   * Get all feedback records for a specific analysis.
   * Admin-only endpoint.
   */
  async listByAnalysis(analysisId: string): Promise<FeedbackRecord[]> {
    return prisma.analysisFeedback.findMany({
      where: { analysisId },
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * List feedback records with optional filters and pagination.
   * Admin-only endpoint.
   */
  async list(options: FeedbackListOptions = {}): Promise<{
    records: FeedbackRecord[];
    total: number;
    page: number;
    pageSize: number;
    pages: number;
  }> {
    const page = Math.max(1, options.page ?? 1);
    const pageSize = Math.min(100, Math.max(1, options.pageSize ?? 20));
    const skip = (page - 1) * pageSize;

    const where: Record<string, unknown> = {};
    if (options.feedbackType) where.feedbackType = options.feedbackType;
    if (options.isReviewed !== undefined) where.isReviewed = options.isReviewed;
    if (options.analysisId) where.analysisId = options.analysisId;

    const [records, total] = await Promise.all([
      prisma.analysisFeedback.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
      }),
      prisma.analysisFeedback.count({ where }),
    ]);

    return {
      records,
      total,
      page,
      pageSize,
      pages: Math.ceil(total / pageSize),
    };
  }

  /**
   * Find a single feedback record by ID.
   */
  async findById(id: string): Promise<FeedbackRecord | null> {
    return prisma.analysisFeedback.findUnique({ where: { id } });
  }

  /**
   * Mark a feedback record as reviewed (admin action).
   * Users CANNOT call this endpoint.
   */
  async markReviewed(
    id: string,
    reviewedBy: string,
    reviewNote?: string
  ): Promise<FeedbackRecord> {
    const updated = await prisma.analysisFeedback.update({
      where: { id },
      data: {
        isReviewed: true,
        reviewedBy,
        reviewNote: reviewNote ?? null,
      },
    });

    logger.info('AnalysisFeedback marked as reviewed', {
      id,
      reviewedBy,
      hasNote: Boolean(reviewNote),
    });

    return updated;
  }

  /**
   * Get count of feedback by type for an analysis (for summary stats).
   */
  async getCountsByType(analysisId: string): Promise<Record<string, number>> {
    const rows = await prisma.analysisFeedback.groupBy({
      by: ['feedbackType'],
      where: { analysisId },
      _count: { feedbackType: true },
    });

    const counts: Record<string, number> = {};
    for (const row of rows) {
      counts[row.feedbackType] = row._count.feedbackType;
    }
    return counts;
  }
}

export const feedbackRepository = new FeedbackRepository();
