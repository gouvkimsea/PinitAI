import {
  HybridEvidencePacket,
  StructuredAiAnalysis,
} from './hybridTypes';
import { logger } from '../../utils/logger';

export interface AggregatedHybridVerdict {
  finalClassification: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  finalScore: number; // 0 to 100
  finalConfidence: number; // 0 to 100
  primaryCategory: string;
  categories: string[];
  indicators: string[];
  reasoningSummary: string;
  recommendedAction: string;
  isUncertain: boolean;
  deterministicOverrideApplied: boolean;
  overrideReason?: string;
  dimensions: StructuredAiAnalysis['dimensions'];
  groundingMetadata: StructuredAiAnalysis['grounding'];
}

export class HybridSignalAggregator {
  private static instance: HybridSignalAggregator | null = null;

  private constructor() {}

  public static getInstance(): HybridSignalAggregator {
    if (!HybridSignalAggregator.instance) {
      HybridSignalAggregator.instance = new HybridSignalAggregator();
    }
    return HybridSignalAggregator.instance;
  }

  /**
   * Aggregates AI semantic analysis with deterministic security layers:
   * Rule Engine + Threat Intelligence + URL Analysis + Message Analysis + Behavioral Signals + AI Semantic Analysis
   *
   * Strictly enforces:
   * 1. The Anti-Override Guard (AI benign output cannot override strong trusted security indicators).
   * 2. The Uncertainty Preservation Rule (Ambiguity in AI cannot be replaced with false certainty).
   */
  public aggregate(
    aiAnalysis: StructuredAiAnalysis,
    packet: HybridEvidencePacket
  ): AggregatedHybridVerdict {
    const isDeterministicConfirmedMalicious =
      packet.deterministicBaseline.isConfirmedMalicious ||
      packet.threatIntelSignals.knownMalicious ||
      packet.ruleSignals.triggeredRules.some((r) => r.severity === 'critical');

    let finalClassification = aiAnalysis.classification;
    let finalConfidence = aiAnalysis.confidence;
    let finalScore = packet.deterministicBaseline.preliminaryScore;
    let deterministicOverrideApplied = false;
    let overrideReason: string | undefined;

    // ──────────────────────────────────────────────────────────────────────────
    // 1. ANTI-OVERRIDE GUARD: AI cannot unilaterally downgrade verified threats
    // ──────────────────────────────────────────────────────────────────────────
    if (isDeterministicConfirmedMalicious && (aiAnalysis.classification === 'CLEAN' || aiAnalysis.classification === 'SUSPICIOUS')) {
      deterministicOverrideApplied = true;
      finalClassification = 'MALICIOUS';
      finalScore = Math.max(85, packet.deterministicBaseline.preliminaryScore);
      finalConfidence = Math.max(90, aiAnalysis.confidence);
      overrideReason = 'Deterministic security intelligence (verified detection rules or threat intelligence feeds) identified confirmed threats, overriding benign AI semantic classification.';

      logger.warn('Anti-Override Guard activated: Overrode benign AI output with verified security intelligence', {
        aiClassification: aiAnalysis.classification,
        finalClassification,
        rulesTriggered: packet.ruleSignals.triggeredRules.map((r) => r.ruleId),
      });
    } else if (!isDeterministicConfirmedMalicious && aiAnalysis.classification === 'MALICIOUS') {
      // If deterministic signals saw no threat, and AI claimed MALICIOUS with uncertainty or prompt injection
      if (aiAnalysis.uncertainty.is_uncertain || aiAnalysis.confidence < 70) {
        finalClassification = 'SUSPICIOUS';
        finalScore = Math.min(65, Math.max(finalScore, 45));
        finalConfidence = Math.min(60, aiAnalysis.confidence);
      } else {
        // High confidence AI with multiple semantic manipulation tactics
        finalScore = Math.max(finalScore, 75);
      }
    } else if (aiAnalysis.classification === 'CLEAN') {
      finalScore = Math.min(finalScore, 20);
    } else if (aiAnalysis.classification === 'SUSPICIOUS') {
      finalScore = Math.max(finalScore, 50);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // 2. UNCERTAINTY PRESERVATION: Ensure ambiguity is respected
    // ──────────────────────────────────────────────────────────────────────────
    let isUncertain = aiAnalysis.uncertainty.is_uncertain;
    if (packet.deterministicBaseline.preliminarySeverity === 'safe' && aiAnalysis.dimensions.ambiguity.is_ambiguous) {
      isUncertain = true;
      finalConfidence = Math.min(finalConfidence, 55);
      if (finalClassification === 'MALICIOUS') {
        finalClassification = 'SUSPICIOUS';
      }
    }

    // Synthesize combined indicators without duplication
    const combinedIndicators = Array.from(
      new Set([
        ...packet.ruleSignals.triggeredRules.map((r) => `[${r.ruleId}] ${r.description}`),
        ...(packet.threatIntelSignals.listedOnFeeds.length > 0
          ? [`Threat Intelligence feed listing: ${packet.threatIntelSignals.listedOnFeeds.join(', ')}`]
          : []),
        ...aiAnalysis.indicators,
      ])
    );

    // Categories
    const combinedCategories = Array.from(
      new Set([
        ...aiAnalysis.categories,
        ...packet.ruleSignals.triggeredRules.map((r) => String(r.category)),
      ])
    ).filter(Boolean);

    const primaryCategory = combinedCategories[0] || aiAnalysis.dimensions.scam_category || 'general_threat';

    let reasoningSummary = aiAnalysis.reasoning_summary;
    if (deterministicOverrideApplied && overrideReason) {
      reasoningSummary = `${overrideReason} ${reasoningSummary}`;
    }

    return {
      finalClassification,
      finalScore,
      finalConfidence,
      primaryCategory,
      categories: combinedCategories,
      indicators: combinedIndicators,
      reasoningSummary,
      recommendedAction: aiAnalysis.recommended_action,
      isUncertain,
      deterministicOverrideApplied,
      overrideReason,
      dimensions: aiAnalysis.dimensions,
      groundingMetadata: {
        ...aiAnalysis.grounding,
        deterministic_override_applied: deterministicOverrideApplied,
      },
    };
  }
}

export const hybridSignalAggregator = HybridSignalAggregator.getInstance();
