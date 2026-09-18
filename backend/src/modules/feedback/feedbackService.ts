import prisma from '../../database/client';
import { aiProxyService } from '../ai/aiProxyService';
import { logger } from '../../utils/logger';
import { feedbackRepository, CreateFeedbackDTO } from './feedbackRepository';
import { metricsCollector } from '../monitoring/metricsCollector';

export type FeedbackType = 'correct_detection' | 'incorrect_detection' | 'report_scam' | 'not_sure';

export interface StructuredFeedbackDTO {
  analysis_id: string;
  feedback_type: FeedbackType;
  reported_category?: string | null;
  explanation?: string | null;
  target_snippet?: string | null;
  risk_score_at_time?: number | null;
  userId?: string | null;
  rawIp?: string | null;
}

export interface FeedbackDTO {
  scan_id: string;
  is_correct: boolean;
  suggested_category?: string;
  comments?: string;
  userId?: string | null;
}

/** Rate limit: max submissions per IP per window (DB-level, layer 2) */
const DB_RATE_LIMIT = {
  maxCount: 20,
  windowMs: 15 * 60 * 1000, // 15 minutes
};

/** Duplicate protection window: same analysis + same identity within this window */
const DUPLICATE_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours

export class FeedbackService {
  /**
   * Submit structured 4-type user feedback for an analysis result.
   *
   * Pipeline:
   * 1. Validate feedback type (schema-validated upstream, defense-in-depth here)
   * 2. DB-level rate limit: max 20 submissions per IP per 15 minutes
   * 3. Duplicate protection: same analysis_id + same identity within 24h → reject
   * 4. Persist to AnalysisFeedback table
   * 5. For report_scam: also create ScamReport record (staging only — does NOT touch ScamPattern)
   * 6. Forward telemetry to AI engine dataset (existing behavior)
   *
   * SECURITY: This service never writes to ScamPattern or ThreatIntelligence.
   * Feedback is staged for human review only.
   */
  async submitStructuredFeedback(dto: StructuredFeedbackDTO): Promise<{
    success: boolean;
    message: string;
    feedback_id: string;
    duplicate?: boolean;
  }> {
    const { analysis_id, feedback_type, userId, rawIp } = dto;

    logger.info('Structured feedback submission received', {
      analysisId: analysis_id,
      feedbackType: feedback_type,
      hasUser: Boolean(userId),
      hasIp: Boolean(rawIp),
    });

    // ── Layer 2: DB-level rate limit check ──────────────────────────────────
    if (rawIp) {
      const recentCount = await feedbackRepository.countRecentByIp(rawIp, DB_RATE_LIMIT.windowMs);
      if (recentCount >= DB_RATE_LIMIT.maxCount) {
        logger.warn('DB-level feedback rate limit exceeded', {
          ipHash: '[hashed]',
          recentCount,
          maxCount: DB_RATE_LIMIT.maxCount,
        });
        const error = new Error('Feedback rate limit exceeded. Please wait before submitting more feedback.') as Error & { statusCode?: number; code?: string };
        error.statusCode = 429;
        error.code = 'FEEDBACK_RATE_LIMIT_EXCEEDED';
        throw error;
      }
    }

    // ── Duplicate protection ─────────────────────────────────────────────────
    const duplicate = await feedbackRepository.findDuplicate(
      analysis_id,
      rawIp,
      userId,
      DUPLICATE_WINDOW_MS
    );

    if (duplicate) {
      logger.info('Duplicate feedback submission blocked', {
        analysisId: analysis_id,
        existingId: duplicate.id,
        existingType: duplicate.feedbackType,
      });
      return {
        success: false,
        message: 'You have already submitted feedback for this analysis within the last 24 hours.',
        feedback_id: duplicate.id,
        duplicate: true,
      };
    }

    // ── Persist to AnalysisFeedback ──────────────────────────────────────────
    const createDTO: CreateFeedbackDTO = {
      analysisId: analysis_id,
      userId: userId ?? null,
      rawIp: rawIp ?? null,
      feedbackType: feedback_type,
      reportedCategory: dto.reported_category ?? null,
      explanation: dto.explanation ?? null,
      targetSnippet: dto.target_snippet ?? null,
      riskScoreAtTime: dto.risk_score_at_time ?? null,
    };

    const record = await feedbackRepository.create(createDTO);

    // Record reliability metrics
    if (feedback_type === 'incorrect_detection') {
      if ((dto.risk_score_at_time ?? 0) >= 50) {
        metricsCollector.recordFalsePositive();
      } else {
        metricsCollector.recordFalseNegative();
      }
    } else if (feedback_type === 'report_scam') {
      metricsCollector.recordFalseNegative();
    }

    // ── For report_scam: create a staged ScamReport ──────────────────────────
    // This writes to scam_reports (community staging), NOT scam_patterns.
    if (feedback_type === 'report_scam') {
      await this.createStagedScamReport({
        analysisId: analysis_id,
        reportedCategory: dto.reported_category ?? null,
        explanation: dto.explanation ?? null,
        targetSnippet: dto.target_snippet ?? null,
        userId: userId ?? null,
      });
    }

    // ── Forward telemetry to AI engine (non-blocking) ────────────────────────
    this.forwardToAiEngine({
      scan_id: analysis_id,
      feedback_type,
      reported_category: dto.reported_category,
      explanation: dto.explanation,
    }).catch((err) => {
      logger.warn('AI engine telemetry forward failed (non-blocking)', {
        error: (err as Error).message,
      });
    });

    return {
      success: true,
      message: this.getSuccessMessage(feedback_type),
      feedback_id: record.id,
    };
  }

  /**
   * Legacy feedback submission (is_correct boolean) — kept for backward compatibility.
   * Forwards to the new structured system as either correct_detection or incorrect_detection.
   */
  async submitFeedback(dto: FeedbackDTO): Promise<{ success: boolean; message: string }> {
    logger.info('Legacy feedback submission received', {
      scanId: dto.scan_id,
      isCorrect: dto.is_correct,
    });

    try {
      const result = await this.submitStructuredFeedback({
        analysis_id: dto.scan_id,
        feedback_type: dto.is_correct ? 'correct_detection' : 'incorrect_detection',
        reported_category: dto.suggested_category ?? null,
        explanation: dto.comments ?? null,
        userId: dto.userId ?? null,
      });

      if (result.duplicate) {
        return { success: true, message: 'Feedback already recorded for this analysis.' };
      }

      return { success: true, message: result.message };
    } catch (err) {
      // On rate limit or other errors in legacy path, gracefully degrade
      logger.warn('Legacy feedback submission failed', { error: (err as Error).message });
      return { success: true, message: 'Feedback recorded for ScamCheck AI evaluation.' };
    }
  }

  /**
   * Creates a staged ScamReport record from a report_scam feedback submission.
   *
   * SECURITY NOTE: This writes only to `scam_reports` (community staging table).
   * It does NOT write to `scam_patterns` or `threat_intelligence`.
   * Analysts must manually review and promote community reports.
   */
  private async createStagedScamReport(params: {
    analysisId: string;
    reportedCategory: string | null;
    explanation: string | null;
    targetSnippet: string | null;
    userId: string | null;
  }): Promise<void> {
    try {
      await prisma.scamReport.create({
        data: {
          userId: params.userId,
          scamType: params.reportedCategory?.toLowerCase() || 'other',
          target: params.targetSnippet ?? undefined,
          description: params.explanation || `Community report linked to analysis ${params.analysisId}`,
          status: 'PENDING',
        },
      });

      logger.info('Staged ScamReport created from report_scam feedback', {
        analysisId: params.analysisId,
        category: params.reportedCategory,
      });
    } catch (err) {
      // Non-blocking — don't fail the feedback submission if this fails
      logger.warn('Failed to create staged ScamReport', {
        error: (err as Error).message,
        analysisId: params.analysisId,
      });
    }
  }

  /** Forward telemetry to Python AI engine (best-effort, non-blocking) */
  private async forwardToAiEngine(params: {
    scan_id: string;
    feedback_type: FeedbackType;
    reported_category?: string | null;
    explanation?: string | null;
  }): Promise<void> {
    await aiProxyService.forwardFeedback({
      scan_id: params.scan_id,
      is_correct: params.feedback_type === 'correct_detection',
      suggested_category: params.reported_category ?? undefined,
      comments: params.explanation ?? undefined,
    });
  }

  /** Friendly success messages per feedback type */
  private getSuccessMessage(feedbackType: FeedbackType): string {
    const messages: Record<FeedbackType, string> = {
      correct_detection: 'Thank you! Your confirmation helps improve our detection accuracy.',
      incorrect_detection: 'Thank you for the correction. Our analysts will review this result.',
      report_scam: 'Scam report submitted. Our security team will review and investigate.',
      not_sure: 'Feedback recorded. We appreciate your response — it helps us calibrate uncertainty.',
    };
    return messages[feedbackType];
  }
}

export const feedbackService = new FeedbackService();
