import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import {
  UserFeedbackSchema,
  AdminFeedbackListSchema,
  AdminReviewFeedbackSchema,
} from '../validation/analyzeSchemas';
import { feedbackService } from '../modules/feedback/feedbackService';
import { feedbackRepository } from '../modules/feedback/feedbackRepository';
import { logger } from '../utils/logger';
import { sendErrorResponse } from '../utils/responseFormatter';

/**
 * FeedbackController — Handles all user feedback and reporting endpoints.
 *
 * Security principles:
 * - Users submit feedback to a staging table (AnalysisFeedback) only
 * - Users cannot read, modify, or delete existing feedback records
 * - Users cannot write to ScamPattern or ThreatIntelligence
 * - All mutation endpoints require authenticated admin role
 * - Raw IPs are hashed before storage — never persisted in plaintext
 */
export class FeedbackController {
  /**
   * POST /api/v2/feedback
   * Submit structured 4-type feedback for an analysis result.
   *
   * Abuse prevention:
   * - express-rate-limit middleware (layer 1): 20 req/15min per IP
   * - DB-level burst check (layer 2): inside feedbackService
   * - Duplicate protection: same analysis + same identity within 24h → 409
   */
  async submitFeedback(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const validated = UserFeedbackSchema.parse(req.body);

      // Extract IP for rate limiting and duplicate protection
      const rawIp =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        req.socket?.remoteAddress ||
        null;

      const result = await feedbackService.submitStructuredFeedback({
        analysis_id: validated.analysis_id,
        feedback_type: validated.feedback_type,
        reported_category: validated.reported_category ?? null,
        explanation: validated.explanation ?? null,
        target_snippet: validated.target_snippet ?? null,
        risk_score_at_time: validated.risk_score_at_time ?? null,
        userId: req.user?.id ?? null,
        rawIp,
      });

      if (result.duplicate) {
        // 409 Conflict — not an error per se, return helpful message
        res.status(409).json({
          success: false,
          duplicate: true,
          message: result.message,
          feedback_id: result.feedback_id,
          code: 'DUPLICATE_FEEDBACK',
        });
        return;
      }

      res.status(201).json({
        success: true,
        message: result.message,
        feedback_id: result.feedback_id,
      });
    } catch (err) {
      // Handle DB-level rate limit error thrown by feedbackService
      const serviceErr = err as Error & { statusCode?: number; code?: string };
      if (serviceErr.statusCode === 429) {
        sendErrorResponse(
          res,
          429,
          serviceErr.code || 'RATE_LIMIT_EXCEEDED',
          serviceErr.message,
          req
        );
        return;
      }
      next(err);
    }
  }

  /**
   * GET /api/v2/feedback/analysis/:analysisId
   * Get all feedback records for a specific analysis.
   *
   * Public: returns aggregated counts only (not individual records).
   * Admin: returns full records with explanations.
   */
  async getAnalysisFeedbackSummary(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const analysisId = String(req.params.analysisId ?? '').trim();
      if (!analysisId) {
        sendErrorResponse(res, 400, 'MISSING_ANALYSIS_ID', 'analysisId parameter is required.', req);
        return;
      }

      const counts = await feedbackRepository.getCountsByType(analysisId);

      // Public view — counts only, no explanations or IP data
      res.status(200).json({
        success: true,
        analysis_id: analysisId,
        feedback_summary: {
          correct_detection: counts['correct_detection'] ?? 0,
          incorrect_detection: counts['incorrect_detection'] ?? 0,
          report_scam: counts['report_scam'] ?? 0,
          not_sure: counts['not_sure'] ?? 0,
          total: Object.values(counts).reduce((a, b) => a + b, 0),
        },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/admin/feedback
   * Admin: list all feedback records with optional filters.
   * Requires: authenticated admin role.
   */
  async listFeedback(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const validated = AdminFeedbackListSchema.parse(req.query);

      const result = await feedbackRepository.list({
        feedbackType: validated.feedbackType,
        isReviewed: validated.isReviewed === 'true' ? true : validated.isReviewed === 'false' ? false : undefined,
        analysisId: validated.analysisId,
        page: validated.page,
        pageSize: validated.pageSize,
      });

      // Sanitize: remove ipHash from admin response (even admins don't need raw hashes)
      const sanitized = result.records.map((r) => ({
        id: r.id,
        analysisId: r.analysisId,
        userId: r.userId,
        feedbackType: r.feedbackType,
        reportedCategory: r.reportedCategory,
        explanation: r.explanation,
        targetSnippet: r.targetSnippet,
        riskScoreAtTime: r.riskScoreAtTime,
        isReviewed: r.isReviewed,
        reviewedBy: r.reviewedBy,
        reviewNote: r.reviewNote,
        createdAt: r.createdAt,
      }));

      res.status(200).json({
        success: true,
        records: sanitized,
        pagination: {
          total: result.total,
          page: result.page,
          pageSize: result.pageSize,
          pages: result.pages,
        },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * PATCH /api/admin/feedback/:id/review
   * Admin: mark a feedback record as reviewed with optional note.
   * Requires: authenticated admin role.
   */
  async markReviewed(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const feedbackId = String(req.params.id ?? '').trim();
      if (!feedbackId) {
        sendErrorResponse(res, 400, 'MISSING_FEEDBACK_ID', 'Feedback ID is required.', req);
        return;
      }

      const validated = AdminReviewFeedbackSchema.parse(req.body);

      // Verify record exists
      const existing = await feedbackRepository.findById(feedbackId);
      if (!existing) {
        sendErrorResponse(
          res,
          404,
          'FEEDBACK_NOT_FOUND',
          `Feedback record '${feedbackId}' not found.`,
          req
        );
        return;
      }

      const reviewerId = req.user?.id || 'unknown_admin';
      const updated = await feedbackRepository.markReviewed(
        feedbackId,
        reviewerId,
        validated.reviewNote
      );

      logger.info('Admin marked feedback as reviewed', {
        feedbackId,
        reviewedBy: reviewerId,
        analysisId: existing.analysisId,
      });

      res.status(200).json({
        success: true,
        message: 'Feedback record marked as reviewed.',
        id: updated.id,
        isReviewed: updated.isReviewed,
        reviewedBy: updated.reviewedBy,
        reviewNote: updated.reviewNote,
      });
    } catch (err) {
      next(err);
    }
  }
}

export const feedbackController = new FeedbackController();
