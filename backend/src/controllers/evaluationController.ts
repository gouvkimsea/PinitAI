import { Request, Response, NextFunction } from 'express';
import {
  evaluationEngine,
  getBenchmarkDataset,
  validateDatasetIntegrity,
  ComprehensiveEvaluationReport,
} from '../modules/evaluation';

export class EvaluationController {
  private static instance: EvaluationController | null = null;
  private lastReport: ComprehensiveEvaluationReport | null = null;

  private constructor() {}

  public static getInstance(): EvaluationController {
    if (!EvaluationController.instance) {
      EvaluationController.instance = new EvaluationController();
    }
    return EvaluationController.instance;
  }

  /**
   * GET /api/evaluation/dataset
   * Retrieves dataset summary, category distribution, and sample count.
   */
  public getDatasetInfo(req: Request, res: Response): void {
    const integrity = validateDatasetIntegrity();
    const dataset = getBenchmarkDataset();

    const { category, language, label } = req.query;
    let filtered = dataset;

    if (typeof category === 'string') {
      filtered = filtered.filter((s) => s.category.toLowerCase() === category.toLowerCase());
    }
    if (typeof language === 'string') {
      filtered = filtered.filter((s) => s.language === language);
    }
    if (typeof label === 'string') {
      filtered = filtered.filter((s) => s.expectedLabel.toUpperCase() === label.toUpperCase());
    }

    res.status(200).json({
      success: true,
      integrity,
      filteredCount: filtered.length,
      samples: filtered.map((s) => ({
        id: s.id,
        category: s.category,
        expectedLabel: s.expectedLabel,
        language: s.language,
        difficulty: s.difficulty,
        nuanceTags: s.nuanceTags,
        contentPreview: s.content.length > 100 ? s.content.substring(0, 100) + '...' : s.content,
        description: s.description,
      })),
    });
  }

  /**
   * POST /api/evaluation/benchmark
   * Executes the full evaluation benchmark across all curated test cases.
   */
  public async runBenchmark(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const report = await evaluationEngine.runBenchmark();
      this.lastReport = report;

      const format = req.query.format || 'json';
      if (format === 'markdown' || format === 'md') {
        const md = evaluationEngine.formatReportAsMarkdown(report);
        res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
        res.status(200).send(md);
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
   * GET /api/evaluation/metrics
   * Retrieves the latest cached benchmark results or runs a fresh benchmark if none exists.
   */
  public async getLatestMetrics(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!this.lastReport) {
        this.lastReport = await evaluationEngine.runBenchmark();
      }

      res.status(200).json({
        success: true,
        data: this.lastReport,
      });
    } catch (err) {
      next(err);
    }
  }
}

export const evaluationController = EvaluationController.getInstance();
