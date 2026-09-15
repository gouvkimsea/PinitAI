import { Response, NextFunction } from 'express';
import { z } from 'zod';
import { AuthenticatedRequest } from '../middleware/auth';
import {
  scamIntelligenceService,
  SUPPORTED_SCAM_CATEGORIES,
  PatternSeverity,
  PatternStatus,
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

export class IntelligenceController {
  /**
   * GET /api/intelligence/categories
   * List all officially supported scam intelligence categories.
   */
  async getCategories(_req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      res.status(200).json({
        success: true,
        supported_categories: SUPPORTED_SCAM_CATEGORIES,
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
   * Immediately updates detection cache without application code modification.
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
   * Hot-reloads memory cache instantly.
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
}

export const intelligenceController = new IntelligenceController();
