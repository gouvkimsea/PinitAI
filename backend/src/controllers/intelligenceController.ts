import { Response, NextFunction } from 'express';
import { z } from 'zod';
import { AuthenticatedRequest } from '../middleware/auth';
import {
  scamIntelligenceService,
  SUPPORTED_SCAM_CATEGORIES,
  PatternSeverity,
  PatternStatus,
  ruleRegistry,
  ruleTester,
  ruleLogger,
  feedbackTracker,
  scamIntelligenceEngine,
  normalizeCategory,
  ALL_RULE_CATEGORIES,
  CATEGORY_DISPLAY_NAMES,
} from '../modules/intelligence';
import { logger } from '../utils/logger';
import { sendErrorResponse } from '../utils/responseFormatter';

const CreatePatternSchema = z.object({
  pattern: z.string().min(1, 'Pattern string is required.').max(1000),
  category: z.string().min(2, 'Category must be specified.').max(100),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  description: z.string().min(3, 'Description is required.').max(2000),
  source: z.string().min(2, 'Source is required.').max(200),
  status: z.enum(['active', 'inactive', 'pending_review', 'deprecated']).optional(),
});

const UpdatePatternSchema = z.object({
  pattern: z.string().min(1).max(1000).optional(),
  category: z.string().min(2).max(100).optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  description: z.string().min(3).max(2000).optional(),
  source: z.string().min(2).max(200).optional(),
  status: z.enum(['active', 'inactive', 'pending_review', 'deprecated']).optional(),
});

const CompareContentSchema = z.object({
  content: z.string().min(1, 'Content to evaluate is required.').max(50000),
  categories: z.array(z.string()).optional(),
  min_severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  max_matches: z.number().int().min(1).max(100).optional(),
});

const ToggleRuleSchema = z.object({
  enabled: z.boolean(),
});

const FeedbackSchema = z.object({
  rule_id: z.string().min(1, 'Rule ID is required.'),
  sample_content: z.string().min(1, 'Sample content is required.').max(50000),
  reason: z.string().max(1000).optional(),
  reported_by: z.string().max(200).optional(),
});

const EvaluateContentSchema = z.object({
  text: z.string().min(1, 'Text content is required.').max(50000),
  url: z.string().optional(),
  qr: z.string().optional(),
});

export class IntelligenceController {
  /**
   * GET /api/intelligence/categories
   * List all officially supported scam intelligence categories (both legacy and 20 modular categories).
   */
  async getCategories(_req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      res.status(200).json({
        success: true,
        supported_categories: SUPPORTED_SCAM_CATEGORIES,
        modular_categories: ALL_RULE_CATEGORIES,
        category_metadata: CATEGORY_DISPLAY_NAMES,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/intelligence/patterns
   * Query structured scam intelligence patterns with filtering and pagination.
   */
  async listPatterns(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const category = req.query.category as string | undefined;
      const severity = req.query.severity as PatternSeverity | undefined;
      const status = req.query.status as PatternStatus | undefined;
      const search = req.query.search as string | undefined;
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const offset = parseInt(req.query.offset as string, 10) || 0;

      const result = await scamIntelligenceService.getPatterns({
        category,
        severity,
        status,
        search,
        limit,
        offset,
      });

      res.status(200).json({
        success: true,
        data: result.patterns,
        pagination: {
          total: result.total,
          limit,
          offset,
        },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/intelligence/patterns/:id
   * Retrieve a specific scam intelligence pattern by ID.
   */
  async getPatternById(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = req.params.id as string;
      const pattern = await scamIntelligenceService.getPatternById(id);

      if (!pattern) {
        sendErrorResponse(res, 404, 'PATTERN_NOT_FOUND', 'Scam intelligence pattern not found.', req);
        return;
      }

      res.status(200).json({
        success: true,
        data: pattern,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/intelligence/patterns
   * Create and register a new scam pattern in the database.
   */
  async createPattern(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = CreatePatternSchema.parse(req.body);

      const created = await scamIntelligenceService.createPattern({
        pattern: parsed.pattern,
        category: parsed.category.toLowerCase(),
        severity: parsed.severity,
        description: parsed.description,
        source: parsed.source,
        status: parsed.status || 'active',
      });

      logger.info('New scam intelligence pattern created', {
        id: created.id,
        category: created.category,
        severity: created.severity,
      });

      res.status(201).json({
        success: true,
        message: 'Scam intelligence pattern registered and active in detection pipeline.',
        data: created,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * PUT /api/intelligence/patterns/:id
   * Update an existing scam intelligence pattern.
   */
  async updatePattern(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = req.params.id as string;
      const parsed = UpdatePatternSchema.parse(req.body);

      const updated = await scamIntelligenceService.updatePattern(id, {
        pattern: parsed.pattern,
        category: parsed.category ? parsed.category.toLowerCase() : undefined,
        severity: parsed.severity,
        description: parsed.description,
        source: parsed.source,
        status: parsed.status,
      });

      if (!updated) {
        sendErrorResponse(res, 404, 'PATTERN_NOT_FOUND', 'Scam intelligence pattern not found to update.', req);
        return;
      }

      logger.info('Scam intelligence pattern updated', { id, category: updated.category });

      res.status(200).json({
        success: true,
        message: 'Scam intelligence pattern updated successfully.',
        data: updated,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * DELETE /api/intelligence/patterns/:id
   * Remove a scam pattern from the database.
   */
  async deletePattern(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = req.params.id as string;
      const deleted = await scamIntelligenceService.deletePattern(id);

      if (!deleted) {
        sendErrorResponse(res, 404, 'PATTERN_NOT_FOUND', 'Scam intelligence pattern not found to delete.', req);
        return;
      }

      logger.info('Scam intelligence pattern deleted', { id });

      res.status(200).json({
        success: true,
        message: 'Scam intelligence pattern deleted successfully.',
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/intelligence/compare
   * Service endpoint: Compares submitted content against known scam patterns in the database.
   */
  async compareContent(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = CompareContentSchema.parse(req.body);

      const result = await scamIntelligenceService.matchContent(parsed.content, {
        categories: parsed.categories,
        minSeverity: parsed.min_severity,
        maxMatches: parsed.max_matches,
      });

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/intelligence/seed
   * Re-seed or reset the database catalog with the comprehensive baseline.
   */
  async seedCatalog(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const forceReset = req.body.force_reset === true;
      const result = await scamIntelligenceService.seedCatalog(forceReset);

      res.status(200).json({
        success: true,
        message: `Catalog seed completed. ${result.count} patterns inserted/updated.`,
        data: result,
      });
    } catch (err) {
      next(err);
    }
  }

  // =========================================================================
  // Modular Rule System Endpoints
  // =========================================================================

  /**
   * GET /api/intelligence/rules
   * Query modular detection rules with filtering.
   */
  async listRules(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const categoryParam = req.query.category as string | undefined;
      const severityParam = req.query.severity as PatternSeverity | undefined;
      const enabledOnly = req.query.enabled_only === 'true';
      const search = req.query.search as string | undefined;

      const category = categoryParam ? normalizeCategory(categoryParam) || undefined : undefined;

      const rules = ruleRegistry.getAllRules({
        category,
        severity: severityParam,
        enabledOnly,
        search,
      });

      const stats = ruleRegistry.getRuleStats();

      res.status(200).json({
        success: true,
        total: rules.length,
        stats,
        data: rules.map((r) => ({
          id: r.id,
          category: r.category,
          category_display: CATEGORY_DISPLAY_NAMES[r.category],
          description: r.description,
          severity: r.severity,
          version: r.version,
          enabled: r.enabled,
          confidence_contribution: r.confidenceContribution,
          tags: r.tags,
          test_cases_count: r.testCases?.length || 0,
        })),
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/intelligence/rules/:id
   * Get modular rule details, version history, and metrics.
   */
  async getRuleById(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = req.params.id as string;
      const rule = ruleRegistry.getRule(id);

      if (!rule) {
        sendErrorResponse(res, 404, 'RULE_NOT_FOUND', `Modular rule [${id}] not found.`, req);
        return;
      }

      const versionHistory = ruleRegistry.getVersionHistory(id);
      const metrics = feedbackTracker.getRuleMetrics(id);

      res.status(200).json({
        success: true,
        data: {
          id: rule.id,
          category: rule.category,
          category_display: CATEGORY_DISPLAY_NAMES[rule.category],
          description: rule.description,
          severity: rule.severity,
          version: rule.version,
          enabled: rule.enabled,
          confidence_contribution: rule.confidenceContribution,
          tags: rule.tags,
          test_cases: rule.testCases,
          version_history: versionHistory,
          metrics,
        },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/intelligence/rules/:id/toggle
   * Enable or disable a rule at runtime without code restart.
   */
  async toggleRule(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = req.params.id as string;
      const parsed = ToggleRuleSchema.parse(req.body);

      const success = ruleRegistry.setRuleEnabled(id, parsed.enabled);
      if (!success) {
        sendErrorResponse(res, 404, 'RULE_NOT_FOUND', `Modular rule [${id}] not found to toggle.`, req);
        return;
      }

      res.status(200).json({
        success: true,
        message: `Rule [${id}] ${parsed.enabled ? 'enabled' : 'disabled'} successfully.`,
        data: { id, enabled: parsed.enabled },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/intelligence/rules/:id/test
   * Execute self-testing fixtures for a specific rule.
   */
  async testRule(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = req.params.id as string;
      const report = await ruleTester.testRuleById(id);

      if (!report) {
        sendErrorResponse(res, 404, 'RULE_NOT_FOUND', `Modular rule [${id}] not found to test.`, req);
        return;
      }

      res.status(200).json({
        success: true,
        data: report,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/intelligence/rules/test-all
   * Execute self-testing suites across all registered rules.
   */
  async testAllRules(_req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const report = await ruleTester.testAllRegisteredRules();
      res.status(200).json({
        success: true,
        data: report,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/intelligence/metrics
   * Performance metrics across all rules and evaluation telemetry.
   */
  async getMetrics(_req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const metrics = feedbackTracker.getAllRuleMetrics();
      const recentLogs = ruleLogger.getRecentLogs(20);

      const totalEvals = metrics.reduce((acc, m) => acc + m.evaluationsCount, 0);
      const totalMatches = metrics.reduce((acc, m) => acc + m.matchCount, 0);
      const totalFps = metrics.reduce((acc, m) => acc + m.falsePositivesCount, 0);
      const totalFns = metrics.reduce((acc, m) => acc + m.falseNegativesCount, 0);

      res.status(200).json({
        success: true,
        summary: {
          total_evaluations: totalEvals,
          total_matches: totalMatches,
          total_false_positives: totalFps,
          total_false_negatives: totalFns,
          overall_precision: totalMatches > 0 ? Math.round(((totalMatches - totalFps) / totalMatches) * 1000) / 10 : 100,
        },
        rule_metrics: metrics,
        recent_evaluation_logs: recentLogs,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/intelligence/feedback/false-positive
   * Record a false positive report.
   */
  async reportFalsePositive(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = FeedbackSchema.parse(req.body);
      const record = feedbackTracker.recordFalsePositive(
        parsed.rule_id,
        parsed.sample_content,
        parsed.reason,
        parsed.reported_by || req.user?.id
      );

      res.status(201).json({
        success: true,
        message: `False positive recorded for rule [${parsed.rule_id}].`,
        data: record,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/intelligence/feedback/false-negative
   * Record a false negative report.
   */
  async reportFalseNegative(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = FeedbackSchema.parse(req.body);
      const record = feedbackTracker.recordFalseNegative(
        parsed.rule_id,
        parsed.sample_content,
        parsed.reason,
        parsed.reported_by || req.user?.id
      );

      res.status(201).json({
        success: true,
        message: `False negative recorded for rule [${parsed.rule_id}].`,
        data: record,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/intelligence/evaluate
   * Evaluate content using multi-signal modular rules, strictly enforcing the Anti-Unilateral Principle.
   */
  async evaluateModular(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = EvaluateContentSchema.parse(req.body);
      const verdict = await scamIntelligenceEngine.evaluate({
        text: parsed.text,
        url: parsed.url,
        qr: parsed.qr,
      });

      res.status(200).json({
        success: true,
        data: verdict,
      });
    } catch (err) {
      next(err);
    }
  }
}

export const intelligenceController = new IntelligenceController();
