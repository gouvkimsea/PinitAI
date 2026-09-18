import { RuleCategory, RuleSeverity } from './types';
import { logger } from '../../../utils/logger';

export interface RuleExecutionTrace {
  ruleId: string;
  category: RuleCategory;
  severity: RuleSeverity;
  version: string;
  matched: boolean;
  confidence: number;
  durationMs: number;
  snippets?: string[];
}

export interface EvaluationLogEntry {
  id: string;
  timestamp: Date;
  inputPreview: string;
  totalDurationMs: number;
  evaluatedRulesCount: number;
  matchedRulesCount: number;
  traces: RuleExecutionTrace[];
  isScam: boolean;
  threatLevel: string;
  scamScore: number;
}

export class RuleLogger {
  private static instance: RuleLogger | null = null;
  private readonly MAX_LOG_SIZE = 500;
  private logRingBuffer: EvaluationLogEntry[] = [];

  private constructor() {}

  public static getInstance(): RuleLogger {
    if (!RuleLogger.instance) {
      RuleLogger.instance = new RuleLogger();
    }
    return RuleLogger.instance;
  }

  /**
   * Records a complete evaluation trace.
   */
  public logEvaluation(entry: Omit<EvaluationLogEntry, 'id' | 'timestamp'>): EvaluationLogEntry {
    const fullEntry: EvaluationLogEntry = {
      ...entry,
      id: `eval-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date(),
    };

    this.logRingBuffer.unshift(fullEntry);
    if (this.logRingBuffer.length > this.MAX_LOG_SIZE) {
      this.logRingBuffer.pop();
    }

    if (fullEntry.matchedRulesCount > 0) {
      logger.info('Scam intelligence rule match detected', {
        id: fullEntry.id,
        matchedCount: fullEntry.matchedRulesCount,
        threatLevel: fullEntry.threatLevel,
        scamScore: fullEntry.scamScore,
        matchedRuleIds: fullEntry.traces.filter((t) => t.matched).map((t) => t.ruleId),
      });
    }

    return fullEntry;
  }

  /**
   * Retrieves recent evaluation logs with optional filtering.
   */
  public getRecentLogs(limit = 50, onlyMatches = false): EvaluationLogEntry[] {
    let logs = this.logRingBuffer;
    if (onlyMatches) {
      logs = logs.filter((l) => l.matchedRulesCount > 0);
    }
    return logs.slice(0, limit);
  }

  /**
   * Clears in-memory log buffer (useful in test teardown).
   */
  public clearLogs(): void {
    this.logRingBuffer = [];
  }
}

export const ruleLogger = RuleLogger.getInstance();
