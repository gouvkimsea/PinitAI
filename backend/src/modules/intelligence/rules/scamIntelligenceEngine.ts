import {
  RuleEvaluationContext,
  MultiSignalScamVerdict,
  RuleEvidence,
} from './types';
import { ruleRegistry } from './ruleRegistry';
import { ruleLogger, RuleExecutionTrace } from './ruleLogger';
import { feedbackTracker } from './feedbackTracker';
import { logger } from '../../../utils/logger';

export class ScamIntelligenceEngine {
  private static instance: ScamIntelligenceEngine | null = null;

  private constructor() {}

  public static getInstance(): ScamIntelligenceEngine {
    if (!ScamIntelligenceEngine.instance) {
      ScamIntelligenceEngine.instance = new ScamIntelligenceEngine();
    }
    return ScamIntelligenceEngine.instance;
  }

  /**
   * Evaluates input content across all active modular rules.
   * Strictly enforces the Anti-Unilateral Principle: no single weak rule can declare content a scam.
   */
  public async evaluate(context: RuleEvaluationContext): Promise<MultiSignalScamVerdict> {
    const startTime = Date.now();
    const activeRules = ruleRegistry.getAllRules({ enabledOnly: true });

    const traces: RuleExecutionTrace[] = [];
    const triggeredEvidence: RuleEvidence[] = [];

    for (const rule of activeRules) {
      const ruleStart = Date.now();
      try {
        const detection = await rule.detect(context);
        const durationMs = Date.now() - ruleStart;

        feedbackTracker.recordExecution(rule.id, detection.matched, durationMs);

        traces.push({
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          version: rule.version,
          matched: detection.matched,
          confidence: detection.confidence,
          durationMs,
          snippets: detection.evidence?.snippets,
        });

        if (detection.matched && detection.evidence) {
          triggeredEvidence.push(detection.evidence);
        }
      } catch (err) {
        const durationMs = Date.now() - ruleStart;
        feedbackTracker.recordExecution(rule.id, false, durationMs);
        logger.error(`Error evaluating rule [${rule.id}]`, { error: err });
      }
    }

    const evaluationTimeMs = Date.now() - startTime;

    // Build categories detected
    const categoriesDetected = Array.from(new Set(triggeredEvidence.map((e) => e.category)));
    const categoryCount = categoriesDetected.length;

    // Classify signals by severity tier
    let weakCount = 0;
    let mediumCount = 0;
    let strongCount = 0;
    let criticalCount = 0;

    for (const ev of triggeredEvidence) {
      if (ev.severity === 'low' || ev.confidenceContribution < 30) {
        weakCount++;
      } else if (ev.severity === 'medium' || ev.confidenceContribution < 55) {
        mediumCount++;
      } else if (ev.severity === 'high' || ev.confidenceContribution < 75) {
        strongCount++;
      } else {
        criticalCount++;
      }
    }

    // Correlation multiplier based on distinct categories
    let correlationMultiplier = 1.0;
    if (categoryCount >= 4) {
      correlationMultiplier = 1.4;
    } else if (categoryCount === 3) {
      correlationMultiplier = 1.3;
    } else if (categoryCount === 2) {
      correlationMultiplier = 1.15;
    }

    let isSingleWeakRule = false;
    let scamScore = 0;
    let confidence = 0;
    let threatLevel: 'CLEAN' | 'LOW' | 'SUSPICIOUS' | 'MALICIOUS' = 'CLEAN';
    let isScam = false;
    let explanation = '';

    if (triggeredEvidence.length === 0) {
      threatLevel = 'CLEAN';
      scamScore = 0;
      confidence = 90;
      isScam = false;
      explanation = 'No scam intelligence patterns or deceptive triggers matched.';
    } else if (triggeredEvidence.length === 1 && (weakCount === 1 || triggeredEvidence[0].severity === 'low')) {
      // ──────────────────────────────────────────────────────────────────────────
      // ANTI-UNILATERAL PRINCIPLE: A single weak rule NEVER classifies as scam.
      // ──────────────────────────────────────────────────────────────────────────
      isSingleWeakRule = true;
      const single = triggeredEvidence[0];
      scamScore = Math.min(25, single.confidenceContribution);
      confidence = 50;
      threatLevel = 'LOW';
      isScam = false;
      explanation = `Single weak indicator detected (${single.category}: "${single.snippets.join(', ')}"). Under the Anti-Unilateral Principle, content is not classified as a scam without independent corroborating signals.`;
    } else {
      // Combine multiple independent signals
      const sortedByWeight = [...triggeredEvidence].sort(
        (a, b) => b.confidenceContribution - a.confidenceContribution
      );
      const primary = sortedByWeight[0];
      let accumulatedScore = primary.confidenceContribution;

      for (let i = 1; i < sortedByWeight.length; i++) {
        const other = sortedByWeight[i];
        // Diminishing returns from secondary signals
        const contribution = (other.confidenceContribution * 0.25) / Math.sqrt(i);
        accumulatedScore += contribution;
      }

      // Apply cross-category correlation amplification
      accumulatedScore = Math.round(accumulatedScore * correlationMultiplier);
      scamScore = Math.min(100, Math.max(0, accumulatedScore));

      // Confidence increases with number of independent categories and corroboration
      confidence = Math.min(
        98,
        Math.round(65 + categoryCount * 8 + Math.min(15, triggeredEvidence.length * 4))
      );

      if (scamScore >= 70 && (categoryCount >= 2 || criticalCount >= 1 || strongCount >= 2)) {
        threatLevel = 'MALICIOUS';
        isScam = true;
        explanation = `Multi-signal scam detected: Correlated ${triggeredEvidence.length} patterns across ${categoryCount} independent categories (${categoriesDetected.join(', ')}). High risk of fraud.`;
      } else if (scamScore >= 40) {
        threatLevel = 'SUSPICIOUS';
        isScam = false;
        explanation = `Suspicious patterns detected across ${categoryCount} categories (${categoriesDetected.join(', ')}). Caution advised pending further verification.`;
      } else {
        threatLevel = 'LOW';
        isScam = false;
        explanation = `Low-risk indicators matched (${categoriesDetected.join(', ')}), but insufficient corroborating signals to classify as a scam.`;
      }
    }

    const verdict: MultiSignalScamVerdict = {
      isScam,
      threatLevel,
      scamScore,
      confidence,
      triggeredRules: triggeredEvidence,
      categoriesDetected,
      categoryCount,
      primaryCategory: triggeredEvidence[0]?.category,
      isSingleWeakRule,
      explanation,
      signalsBreakdown: {
        weakCount,
        mediumCount,
        strongCount,
        criticalCount,
        correlationMultiplier,
      },
      evaluationTimeMs,
    };

    // Log trace
    const preview = `${context.text || ''} ${context.url || ''}`.substring(0, 100);
    ruleLogger.logEvaluation({
      inputPreview: preview,
      totalDurationMs: evaluationTimeMs,
      evaluatedRulesCount: activeRules.length,
      matchedRulesCount: triggeredEvidence.length,
      traces,
      isScam: verdict.isScam,
      threatLevel: verdict.threatLevel,
      scamScore: verdict.scamScore,
    });

    return verdict;
  }
}

export const scamIntelligenceEngine = ScamIntelligenceEngine.getInstance();
