import { z } from 'zod';
import { StructuredAiAnalysis, HybridEvidencePacket } from './hybridTypes';
import { logger } from '../../utils/logger';

const SemanticDimensionsSchema = z.object({
  intent: z.string().default('Unknown intent'),
  context: z.string().default('General message'),
  manipulation_tactics: z.array(z.string()).default([]),
  impersonation: z.object({
    detected: z.boolean().default(false),
    target: z.string().optional(),
    type: z.enum(['bank', 'government', 'executive', 'support', 'brand', 'other']).optional(),
    confidence: z.number().min(0).max(100).default(0),
  }).default({ detected: false, confidence: 0 }),
  financial_requests: z.object({
    detected: z.boolean().default(false),
    method: z.string().optional(),
    amount: z.string().optional(),
    currency: z.string().optional(),
  }).default({ detected: false }),
  credential_requests: z.object({
    detected: z.boolean().default(false),
    type: z.string().optional(),
  }).default({ detected: false }),
  urgency: z.object({
    level: z.enum(['none', 'low', 'medium', 'high', 'extreme']).default('none'),
    timeframe_claimed: z.string().optional(),
    reason: z.string().optional(),
  }).default({ level: 'none' }),
  threats: z.array(z.string()).default([]),
  suspicious_instructions: z.array(z.string()).default([]),
  social_engineering_patterns: z.array(z.string()).default([]),
  scam_category: z.string().default('general_content'),
  ambiguity: z.object({
    is_ambiguous: z.boolean().default(false),
    reason: z.string().default(''),
    missing_information: z.array(z.string()).default([]),
  }).default({ is_ambiguous: false, reason: '', missing_information: [] }),
});

const RawAiResponseSchema = z.object({
  classification: z.enum(['CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN']).default('UNKNOWN'),
  confidence: z.number().min(0).max(100).default(50),
  categories: z.array(z.string()).default([]),
  indicators: z.array(z.string()).default([]),
  reasoning_summary: z.string().default(''),
  recommended_action: z.string().default('Review carefully before proceeding.'),
  dimensions: SemanticDimensionsSchema.optional(),
  uncertainty: z.object({
    is_uncertain: z.boolean().default(false),
    confidence_level: z.enum(['very_low', 'low', 'medium', 'high', 'verified']).default('medium'),
    missing_evidence: z.array(z.string()).default([]),
  }).optional(),
});

export class AiResponseValidator {
  private static instance: AiResponseValidator | null = null;

  private constructor() {}

  public static getInstance(): AiResponseValidator {
    if (!AiResponseValidator.instance) {
      AiResponseValidator.instance = new AiResponseValidator();
    }
    return AiResponseValidator.instance;
  }

  /**
   * Sanitizes and parses raw text from LLM into a verified JSON object.
   */
  public parseRawText(rawText: string): any {
    if (!rawText || !rawText.trim()) {
      throw new Error('Empty AI response received');
    }

    const hadCot = /<thinking>|<thought>|thought:|scratchpad/i.test(rawText);

    // 1. Strip hidden chain-of-thought, thinking tokens, or scratchpads
    let cleaned = rawText
      .replace(/<thinking>[\s\S]*?<\/thinking>/gi, '')
      .replace(/<thought>[\s\S]*?<\/thought>/gi, '')
      .replace(/^thought:[\s\S]*?\n\n/im, '')
      .trim();

    // 2. Strip Markdown code fences if present
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

    // 3. Extract JSON object substring if model added preamble/postamble
    const firstBrace = cleaned.indexOf('{');
    const lastBrace = cleaned.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      cleaned = cleaned.substring(firstBrace, lastBrace + 1);
    }

    const parsed = JSON.parse(cleaned);
    if (hadCot && typeof parsed === 'object' && parsed !== null) {
      parsed._cotStripped = true;
    }
    return parsed;
  }

  /**
   * Validates and applies all safety filters against hallucination and unsupported certainty.
   */
  public validateAndHarden(
    rawParsed: any,
    evidencePacket: HybridEvidencePacket
  ): StructuredAiAnalysis {
    // 1. Schema Validation
    const parsed = RawAiResponseSchema.parse(rawParsed);

    let urlHallucinationsFiltered = 0;
    let intelHallucinationsFiltered = 0;
    let cotStripped = Boolean((rawParsed as any)?._cotStripped);

    // Check if chain of thought existed in fields
    let reasoning = parsed.reasoning_summary || '';
    if (/<thinking>|thought:|scratchpad/i.test(reasoning)) {
      reasoning = reasoning
        .replace(/<thinking>[\s\S]*?<\/thinking>/gi, '')
        .replace(/^thought:.*$/gim, '')
        .trim();
      cotStripped = true;
    }

    // 2. Safeguard against Hallucinated URLs
    const authenticUrls = new Set(
      (evidencePacket.extractedUrls || []).map((u) => u.toLowerCase().trim())
    );
    const sanitizedIndicators: string[] = [];

    const URL_REGEX = /\bhttps?:\/\/[^\s"',;<>]+/gi;

    for (const indicator of parsed.indicators) {
      const urlsFound = indicator.match(URL_REGEX);
      if (urlsFound && urlsFound.length > 0) {
        let hasHallucination = false;
        for (const url of urlsFound) {
          const lowerUrl = url.toLowerCase().trim();
          // Verify against authentic URLs
          const isAuthentic = Array.from(authenticUrls).some(
            (auth) => lowerUrl.includes(auth) || auth.includes(lowerUrl)
          );
          if (!isAuthentic) {
            hasHallucination = true;
            urlHallucinationsFiltered++;
            logger.warn('Filtered hallucinated URL in AI indicator', { hallucinatedUrl: url });
          }
        }
        if (!hasHallucination) {
          sanitizedIndicators.push(indicator);
        }
      } else {
        sanitizedIndicators.push(indicator);
      }
    }

    // Strip hallucinated URLs from reasoning summary
    reasoning = reasoning.replace(URL_REGEX, (foundUrl) => {
      const lower = foundUrl.toLowerCase().trim();
      const isAuthentic = Array.from(authenticUrls).some(
        (auth) => lower.includes(auth) || auth.includes(lower)
      );
      if (!isAuthentic) {
        urlHallucinationsFiltered++;
        return '[redacted_unverified_url]';
      }
      return foundUrl;
    });

    // 3. Safeguard against Hallucinated Threat Intelligence
    // E.g. AI claims "Listed on Spamhaus" or "Confirmed in VirusTotal" when threat intel didn't supply it
    const authenticFeeds = new Set(
      (evidencePacket.threatIntelSignals?.listedOnFeeds || []).map((f) => f.toLowerCase().trim())
    );

    const THREAT_INTEL_MENTION_REGEX = /\b(?:spamhaus|virustotal|phishtank|urlhaus|openphish|fbi\s+database|interpol\s+list)\b/gi;

    const filteredIndicatorsAfterIntel: string[] = [];
    for (const ind of sanitizedIndicators) {
      const mentions = ind.match(THREAT_INTEL_MENTION_REGEX);
      if (mentions) {
        let unverifiedMention = false;
        for (const m of mentions) {
          if (!authenticFeeds.has(m.toLowerCase())) {
            unverifiedMention = true;
            intelHallucinationsFiltered++;
            logger.warn('Filtered hallucinated threat intelligence claim in AI indicator', { unverifiedFeed: m });
          }
        }
        if (!unverifiedMention) {
          filteredIndicatorsAfterIntel.push(ind);
        }
      } else {
        filteredIndicatorsAfterIntel.push(ind);
      }
    }

    // 4. Preserve Uncertainty & Guard Against Unsupported Certainty
    const dimensions = parsed.dimensions || {
      intent: 'Unknown intent',
      context: 'General message',
      manipulation_tactics: [],
      impersonation: { detected: false, confidence: 0 },
      financial_requests: { detected: false },
      credential_requests: { detected: false },
      urgency: { level: 'none' as const },
      threats: [],
      suspicious_instructions: [],
      social_engineering_patterns: [],
      scam_category: 'general_content',
      ambiguity: { is_ambiguous: false, reason: '', missing_information: [] },
    };

    let confidence = parsed.confidence;
    let isUncertain = parsed.uncertainty?.is_uncertain ?? false;
    let confidenceLevel = parsed.uncertainty?.confidence_level ?? 'medium';
    const missingEvidence = [...(parsed.uncertainty?.missing_evidence || [])];

    // If dimensions indicate ambiguity, enforce uncertainty preservation
    if (dimensions.ambiguity.is_ambiguous) {
      isUncertain = true;
      confidence = Math.min(confidence, 60);
      confidenceLevel = 'low';
      if (dimensions.ambiguity.reason && !missingEvidence.includes(dimensions.ambiguity.reason)) {
        missingEvidence.push(dimensions.ambiguity.reason);
      }
    }

    // If few indicators and confidence is claimed as extremely high without verified rules
    if (
      confidence > 80 &&
      evidencePacket.ruleSignals.triggeredRules.length === 0 &&
      !evidencePacket.threatIntelSignals.knownMalicious
    ) {
      // Unsupported certainty: clamp confidence
      confidence = 75;
      isUncertain = true;
      confidenceLevel = 'medium';
    }

    let classification = parsed.classification;
    if (isUncertain && classification === 'MALICIOUS' && evidencePacket.deterministicBaseline.preliminaryScore < 50) {
      // Preserve uncertainty: do not allow speculative malicious classification without deterministic corroboration
      classification = 'SUSPICIOUS';
    }

    return {
      classification,
      confidence,
      categories: parsed.categories,
      indicators: filteredIndicatorsAfterIntel,
      reasoning_summary: reasoning,
      recommended_action: parsed.recommended_action,
      dimensions,
      uncertainty: {
        is_uncertain: isUncertain,
        confidence_level: confidenceLevel,
        missing_evidence: missingEvidence,
      },
      grounding: {
        url_hallucinations_filtered: urlHallucinationsFiltered,
        intel_hallucinations_filtered: intelHallucinationsFiltered,
        cot_stripped: cotStripped,
        deterministic_override_applied: false,
        sanitized_prompt_injection: false,
      },
    };
  }
}

export const aiResponseValidator = AiResponseValidator.getInstance();
