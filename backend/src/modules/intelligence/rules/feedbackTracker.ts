import { FeedbackRecord, RuleMetrics } from './types';
import { ruleRegistry } from './ruleRegistry';
import { logger } from '../../../utils/logger';
import { metricsCollector } from '../../monitoring/metricsCollector';

interface RuleExecutionStat {
  evaluations: number;
  matches: number;
  totalTimeMs: number;
  lastEvaluatedAt?: Date;
  lastMatchedAt?: Date;
}

export class FeedbackTracker {
  private static instance: FeedbackTracker | null = null;
  private feedbackRecords: FeedbackRecord[] = [];
  private executionStats: Map<string, RuleExecutionStat> = new Map();

  private constructor() {}

  public static getInstance(): FeedbackTracker {
    if (!FeedbackTracker.instance) {
      FeedbackTracker.instance = new FeedbackTracker();
    }
    return FeedbackTracker.instance;
  }

  /**
   * Records execution telemetry for a rule during an evaluation run.
   */
  public recordExecution(ruleId: string, matched: boolean, durationMs: number): void {
    const stat = this.executionStats.get(ruleId) || {
      evaluations: 0,
      matches: 0,
      totalTimeMs: 0,
    };

    stat.evaluations += 1;
    stat.totalTimeMs += durationMs;
    stat.lastEvaluatedAt = new Date();

    if (matched) {
      stat.matches += 1;
      stat.lastMatchedAt = new Date();
    }

    this.executionStats.set(ruleId, stat);
  }

  /**
   * Records a user/analyst false positive report (rule matched benign content incorrectly).
   */
  public recordFalsePositive(
    ruleId: string,
    sampleContent: string,
    reason?: string,
    reportedBy?: string
  ): FeedbackRecord {
    const record: FeedbackRecord = {
      id: `fp-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      ruleId,
      type: 'false_positive',
      sampleContent,
      reason,
      reportedBy: reportedBy || 'system_analyst',
      createdAt: new Date(),
    };

    this.feedbackRecords.push(record);
    metricsCollector.recordFalsePositive();
    logger.warn(`False positive reported for rule [${ruleId}]`, {
      ruleId,
      reason,
      reportedBy: record.reportedBy,
    });

    return record;
  }

  /**
   * Records a false negative report (scam content missed by rule).
   */
  public recordFalseNegative(
    ruleId: string,
    sampleContent: string,
    reason?: string,
    reportedBy?: string
  ): FeedbackRecord {
    const record: FeedbackRecord = {
      id: `fn-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      ruleId,
      type: 'false_negative',
      sampleContent,
      reason,
      reportedBy: reportedBy || 'system_analyst',
      createdAt: new Date(),
    };

    this.feedbackRecords.push(record);
    metricsCollector.recordFalseNegative();
    logger.warn(`False negative reported for rule [${ruleId}]`, {
      ruleId,
      reason,
      reportedBy: record.reportedBy,
    });

    return record;
  }

  /**
   * Calculates performance metrics for a specific rule.
   */
  public getRuleMetrics(ruleId: string): RuleMetrics | null {
    const rule = ruleRegistry.getRule(ruleId);
    if (!rule) return null;

    const stat = this.executionStats.get(ruleId) || {
      evaluations: 0,
      matches: 0,
      totalTimeMs: 0,
    };

    const fps = this.feedbackRecords.filter((r) => r.ruleId === ruleId && r.type === 'false_positive').length;
    const fns = this.feedbackRecords.filter((r) => r.ruleId === ruleId && r.type === 'false_negative').length;

    const truePositives = Math.max(0, stat.matches - fps);
    const precision = stat.matches > 0 ? (truePositives / stat.matches) * 100 : 100;
    const avgExecutionTimeMs = stat.evaluations > 0 ? stat.totalTimeMs / stat.evaluations : 0;

    return {
      ruleId,
      category: rule.category,
      version: rule.version,
      evaluationsCount: stat.evaluations,
      matchCount: stat.matches,
      falsePositivesCount: fps,
      falseNegativesCount: fns,
      totalExecutionTimeMs: stat.totalTimeMs,
      avgExecutionTimeMs: Math.round(avgExecutionTimeMs * 100) / 100,
      lastEvaluatedAt: stat.lastEvaluatedAt,
      lastMatchedAt: stat.lastMatchedAt,
      precision: Math.round(precision * 10) / 10,
    };
  }

  /**
   * Returns performance metrics across all registered rules.
   */
  public getAllRuleMetrics(): RuleMetrics[] {
    const rules = ruleRegistry.getAllRules();
    return rules.map((r) => this.getRuleMetrics(r.id)!);
  }

  /**
   * Retrieves logged feedback records.
   */
  public getFeedbackRecords(filter?: { ruleId?: string; type?: 'false_positive' | 'false_negative' }): FeedbackRecord[] {
    let result = this.feedbackRecords;
    if (filter?.ruleId) {
      result = result.filter((r) => r.ruleId === filter.ruleId);
    }
    if (filter?.type) {
      result = result.filter((r) => r.type === filter.type);
    }
    return result;
  }

  /**
   * Resets metrics and records (useful for test isolation).
   */
  public reset(): void {
    this.feedbackRecords = [];
    this.executionStats.clear();
  }
}

export const feedbackTracker = FeedbackTracker.getInstance();
