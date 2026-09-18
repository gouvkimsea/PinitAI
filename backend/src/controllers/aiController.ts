import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import { sendErrorResponse } from '../utils/responseFormatter';
import { scamIntelligenceEngine } from '../modules/intelligence/rules/scamIntelligenceEngine';
import { urlIntelligence } from '../modules/url/urlIntelligence';
import {
  aiSemanticAnalyzer,
  hybridSignalAggregator,
  HybridEvidencePacket,
} from '../modules/ai';
import { logger } from '../utils/logger';

export class AiController {
  private static instance: AiController | null = null;

  public static getInstance(): AiController {
    if (!AiController.instance) {
      AiController.instance = new AiController();
    }
    return AiController.instance;
  }

  /**
   * POST /api/ai/analyze
   * Evaluates content using the 7-layer Hybrid Scam Detection Architecture:
   * Rule Engine + Threat Intelligence + URL Analysis + Message Analysis +
   * Behavioral Signals + AI Semantic Analysis (12 dimensions) + Evidence Aggregator.
   */
  public async analyze(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { content, type, language, extractedUrls: clientUrls } = req.body || {};

      if (!content || typeof content !== 'string' || !content.trim()) {
        sendErrorResponse(res, 400, 'CONTENT_REQUIRED', 'Content cannot be empty.', req);
        return;
      }

      const targetType = (type || 'TEXT').toUpperCase() as 'TEXT' | 'URL' | 'FILE' | 'QR';

      // 1. Extract and sanitize URLs
      const urlRegex = /\bhttps?:\/\/[^\s"',;<>]+/gi;
      const detectedUrls = content.match(urlRegex) || [];
      const extractedUrls: string[] = Array.isArray(clientUrls) && clientUrls.length > 0
        ? Array.from(new Set([...clientUrls, ...detectedUrls]))
        : Array.from(new Set(detectedUrls));

      if (targetType === 'URL' && extractedUrls.length === 0 && /^https?:\/\//i.test(content.trim())) {
        extractedUrls.push(content.trim());
      }

      // 2. Deterministic Rule Engine Evaluation (Modular 20-category engine)
      const ruleVerdict = await scamIntelligenceEngine.evaluate({
        text: content,
        url: extractedUrls[0],
        language,
        metadata: { type: targetType, extractedUrls },
      });

      // 3. Threat Intelligence & URL Analysis (if URLs present)
      let knownMalicious = false;
      const listedFeeds: string[] = [];
      let reputationScore = 50;
      let urlSignals: HybridEvidencePacket['urlSignals'] = undefined;

      if (extractedUrls.length > 0) {
        try {
          const primaryUrl = extractedUrls[0];
          const urlIntel = await urlIntelligence.analyze(primaryUrl, {
            skipNetworkProbe: true,
            skipDomainAge: true,
          });
          reputationScore = 100 - urlIntel.compositeScore;
          if (urlIntel.severity === 'critical' || urlIntel.compositeScore >= 80) {
            knownMalicious = true;
          }
          if (urlIntel.brandImpersonation.detected) {
            urlSignals = {
              domain: urlIntel.metadata.domain,
              isIpHost: urlIntel.metadata.isIpAddress,
              isLookalike: Boolean(
                urlIntel.brandImpersonation.lookalikeSubstitution ||
                urlIntel.brandImpersonation.impersonationType === 'lookalike'
              ),
              impersonatedBrand: urlIntel.brandImpersonation.targetedBrand,
            };
          }
        } catch (err) {
          logger.warn('URL intelligence inspection non-blocking error in AI controller', {
            error: (err as Error).message,
          });
        }
      }

      // 4. Behavioral & Linguistic Signals
      const impersonationRule = ruleVerdict.triggeredRules.find((r) => r.category === 'impersonation');
      const socialEngRule = ruleVerdict.triggeredRules.find((r) => r.category === 'social_engineering');

      const behavioralSignals: HybridEvidencePacket['behavioralSignals'] = {
        impersonationDetected: Boolean(impersonationRule),
        impersonatedEntity: impersonationRule ? impersonationRule.snippets[0] : undefined,
        coerciveUrgency: Boolean(socialEngRule),
        isolationTactic: /keep (?:it )?secret|do not tell/i.test(content),
      };

      // 5. Assemble Structured Evidence Packet
      const evidencePacket: HybridEvidencePacket = {
        targetType,
        rawInputSnippet: content.substring(0, 4000),
        sanitizedInput: content,
        detectedLanguage: language || (/[\u1780-\u17FF]/.test(content) ? 'km' : 'en'),
        extractedUrls,
        ruleSignals: {
          triggeredRules: ruleVerdict.triggeredRules.map((r) => ({
            ruleId: r.ruleId,
            category: r.category,
            severity: r.severity,
            description: r.description,
            snippets: r.snippets,
          })),
          categoryCount: ruleVerdict.categoryCount,
          highestRuleSeverity:
            ruleVerdict.signalsBreakdown.criticalCount > 0
              ? 'critical'
              : ruleVerdict.signalsBreakdown.strongCount > 0
              ? 'high'
              : ruleVerdict.signalsBreakdown.mediumCount > 0
              ? 'medium'
              : ruleVerdict.signalsBreakdown.weakCount > 0
              ? 'low'
              : 'none',
        },
        threatIntelSignals: {
          reputationScore,
          knownMalicious,
          listedOnFeeds: listedFeeds,
          communityReportCount: 0,
        },
        urlSignals,
        behavioralSignals,
        deterministicBaseline: {
          preliminaryScore: ruleVerdict.scamScore,
          preliminarySeverity: (ruleVerdict.threatLevel.toLowerCase() as any),
          isConfirmedMalicious: ruleVerdict.isScam,
        },
      };

      // 6. AI Semantic Analysis (Evaluates 12 Dimensions)
      const aiAnalysis = await aiSemanticAnalyzer.analyze(evidencePacket);

      // 7. Hybrid Evidence Aggregation & Anti-Override Guard
      const hybridVerdict = hybridSignalAggregator.aggregate(aiAnalysis, evidencePacket);

      res.status(200).json({
        success: true,
        classification: hybridVerdict.finalClassification,
        score: hybridVerdict.finalScore,
        confidence: hybridVerdict.finalConfidence,
        primary_category: hybridVerdict.primaryCategory,
        categories: hybridVerdict.categories,
        indicators: hybridVerdict.indicators,
        reasoning_summary: hybridVerdict.reasoningSummary,
        recommended_action: hybridVerdict.recommendedAction,
        dimensions: hybridVerdict.dimensions,
        uncertainty: {
          is_uncertain: hybridVerdict.isUncertain,
          confidence_level: aiAnalysis.uncertainty.confidence_level,
          missing_evidence: aiAnalysis.uncertainty.missing_evidence,
        },
        grounding: hybridVerdict.groundingMetadata,
      });
    } catch (err) {
      next(err);
    }
  }
}

export const aiController = AiController.getInstance();
