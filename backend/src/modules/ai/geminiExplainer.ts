import crypto from 'crypto';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import { LruCache } from '../../utils/lruCache';
import { metricsCollector } from '../monitoring/metricsCollector';
import {
  AiStructuredExplanation,
  ExplanationContext,
  ExplanationSignalItem,
  ExplanationScamType,
  ExplanationUncertainty,
} from './types';
import { textNormalizer } from '../../pipeline/normalization/textNormalizer';
import { geminiCircuitBreaker } from './circuitBreaker';


/** Structured evidence brief — the ONLY data sent to the LLM. Raw user content is never included. */
export interface EvidenceBrief {
  risk_score: number;
  classification: string;
  threat_level: string;
  confidence_score: number;
  threat_category: string;
  target_type: string;
  language: string;
  detectors_triggered: string[];
  verified_signals: Array<{
    signal: string;
    severity: string;
    source_detector: string;
  }>;
  evidence_summary: string;
  indicators_count: number;
  signal_count: number;
  evidence_breakdown?: Record<string, number>;
}

/**
 * Gemini LLM client for the AI explanation layer.
 *
 * Key contract:
 * - AI receives ONLY the evidence brief — never raw user content.
 * - AI must reference ONLY provided signals — fabrication is prohibited.
 * - AI must mark result as uncertain when evidence is insufficient.
 * - Falls back to null on any failure so the rules engine can take over.
 */
export class GeminiExplainer {
  private readonly GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta';
  private cache = new LruCache<string, Partial<AiStructuredExplanation>>({ maxSize: 500, defaultTtlMs: 3600_000 });

  /**
   * Retrieves current AI explanation cache performance stats
   */
  getCacheStats() {
    return this.cache.getStats();
  }

  /**
   * Clears the AI explanation cache (useful for testing)
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Builds the evidence brief from the ExplanationContext.
   * The brief contains ONLY structured metadata — no raw user text is ever included.
   */
  buildEvidenceBrief(
    ctx: ExplanationContext,
    verifiedSignals: ExplanationSignalItem[]
  ): EvidenceBrief {
    return {
      risk_score: ctx.riskScore ?? 0,
      classification: ctx.classification ?? 'Low Risk',
      threat_level: ctx.threatLevel ?? 'SAFE',
      confidence_score: ctx.confidenceScore ?? 50,
      threat_category: ctx.threatCategory ?? 'UNKNOWN',
      target_type: ctx.targetType,
      language: ctx.language ?? 'en',
      detectors_triggered: (ctx.detectorResults ?? [])
        .filter((d) => d.score > 0)
        .map((d) => d.detector_name),
      verified_signals: verifiedSignals.map((s) => ({
        signal: textNormalizer.redactPii(s.signal),
        severity: s.severity,
        source_detector: s.source_detector ?? 'detection_pipeline',
      })),
      evidence_summary: `Evaluated ${verifiedSignals.length} verified signals across ${
        (ctx.detectorResults ?? []).length
      } detectors.`,
      indicators_count: ctx.indicators?.length ?? 0,
      signal_count: verifiedSignals.length,
      evidence_breakdown: ctx.evidenceBreakdown,
    };
  }

  /**
   * Constructs the strict system prompt that prohibits hallucination.
   */
  private buildSystemPrompt(): string {
    return `You are a structured scam-detection AI assistant. Your ONLY job is to interpret structured security evidence and generate a grounded explanation.

CRITICAL RULES — NEVER VIOLATE:
1. You MUST reference ONLY signals listed in the provided evidence brief. Never invent new signals.
2. You MUST NOT alter, override, or contradict the provided risk_score, classification, or threat_level.
3. You MUST set uncertainty_notes.is_uncertain = true when: signal_count < 2, confidence_score < 60, OR classification is "Low Risk" / "Mild Risk".
4. You MUST respond with ONLY valid JSON matching the schema exactly. No markdown fences, no prose outside the JSON.
5. If signals array is empty, explain that analysis found no specific threat signatures and state uncertainty explicitly.
6. Never claim certainty when evidence is ambiguous. Explicitly say the result is uncertain.

OUTPUT SCHEMA (respond with this exact structure):
{
  "why_suspicious": "string — 2-4 sentence explanation referencing only provided signals",
  "scam_type": {
    "category": "string — one of: phishing, account_takeover, fake_investment, fake_job, impersonation, payment_scam, malware_hazard, safe_content, general_threat",
    "name": "string — human-readable scam type name",
    "description": "string — one sentence describing the modus operandi",
    "threat_level": "string — one of: SAFE, LOW, SUSPICIOUS, HIGH, CRITICAL"
  },
  "actionable_advice": ["string — up to 4 clear protective steps"],
  "uncertainty_notes": {
    "is_uncertain": boolean,
    "reason": "string — explain what evidence is missing or ambiguous",
    "missing_information": ["string — list of what would confirm or deny the threat"],
    "confidence_level": "string — one of: very_low, low, medium, high, verified"
  },
  "summary": "string — 1-2 sentence plain-language verdict"
}`;
  }

  /**
   * Constructs the user-facing prompt with the evidence brief embedded.
   */
  private buildUserPrompt(brief: EvidenceBrief): string {
    const signalList =
      brief.verified_signals.length > 0
        ? brief.verified_signals
            .map((s) => `  - [${s.severity.toUpperCase()}] "${s.signal}" (source: ${s.source_detector})`)
            .join('\n')
        : '  (none — no specific threat signatures detected)';

    const detectorList =
      brief.detectors_triggered.length > 0
        ? brief.detectors_triggered.join(', ')
        : 'none triggered with score > 0';

    return `Analyze the following security evidence brief and generate a grounded 5-part explanation.

EVIDENCE BRIEF:
- Risk Score: ${brief.risk_score}/100
- Classification: ${brief.classification}
- Threat Level: ${brief.threat_level}
- Confidence: ${brief.confidence_score}%
- Threat Category: ${brief.threat_category}
- Content Type: ${brief.target_type}
- Language: ${brief.language}
- Detectors Triggered: ${detectorList}
- Signal Count: ${brief.signal_count}
- Indicators Found: ${brief.indicators_count}

VERIFIED SIGNALS (reference ONLY these — never fabricate additional signals):
${signalList}

Evidence Summary: ${brief.evidence_summary}

Generate the JSON explanation now. Remember: if signal_count is ${brief.signal_count} and confidence is ${brief.confidence_score}%, set uncertainty accordingly.`;
  }

  /**
   * Calls the Gemini API and returns parsed AiStructuredExplanation fields,
   * or null on any failure (network error, parse error, timeout, missing key).
   */
  async explain(
    ctx: ExplanationContext,
    verifiedSignals: ExplanationSignalItem[]
  ): Promise<Partial<AiStructuredExplanation> | null> {
    const apiKey = config.geminiApiKey;
    if (!apiKey) {
      logger.debug('GEMINI_API_KEY not set — skipping LLM explanation, using rules engine fallback');
      return null;
    }

    const brief = this.buildEvidenceBrief(ctx, verifiedSignals);
    const cacheKey = crypto.createHash('sha256').update(JSON.stringify(brief)).digest('hex');

    // Check LRU cache for identical evidence brief
    const cached = this.cache.get(cacheKey);
    if (cached) {
      metricsCollector.recordAiCall(0, true);
      metricsCollector.recordCacheLookup(true);
      logger.debug('Gemini AI explanation served from in-memory LRU cache', {
        signalCount: brief.signal_count,
        riskScore: brief.risk_score,
      });
      return cached;
    }

    metricsCollector.recordCacheLookup(false);

    // Fast-fail if Gemini circuit breaker is OPEN
    if (geminiCircuitBreaker.isOpen()) {
      logger.debug('Gemini LLM circuit breaker is OPEN — bypassing LLM explanation, using rules engine fallback');
      return null;
    }

    const systemPrompt = this.buildSystemPrompt();
    const userPrompt = this.buildUserPrompt(brief);

    const requestBody = {
      system_instruction: {
        parts: [{ text: systemPrompt }],
      },
      contents: [
        {
          role: 'user',
          parts: [{ text: userPrompt }],
        },
      ],
      generationConfig: {
        temperature: 0.1, // Low temperature for deterministic, grounded output
        topP: 0.8,
        maxOutputTokens: 1024,
        responseMimeType: 'application/json',
      },
    };

    const url = `${this.GEMINI_API_BASE}/models/${config.geminiModel}:generateContent?key=${apiKey}`;
    const startTime = Date.now();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.geminiTimeoutMs);

      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errText = await response.text().catch(() => 'unknown error');
        geminiCircuitBreaker.recordFailure(`HTTP ${response.status}`);
        metricsCollector.recordAiCall(Date.now() - startTime, false, true);
        logger.trackAiFailure({
          scanId: ctx.scanId,
          provider: 'Google Gemini',
          error: `HTTP ${response.status}: ${errText.slice(0, 200)}`,
          fallbackUsed: true,
        });
        return null;
      }

      const responseData = await response.json() as {
        candidates?: Array<{
          content?: { parts?: Array<{ text?: string }> };
        }>;
      };
      const rawText: string =
        responseData?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';

      if (!rawText) {
        metricsCollector.recordAiCall(Date.now() - startTime, false, true);
        logger.trackAiFailure({
          scanId: ctx.scanId,
          provider: 'Google Gemini',
          error: 'Empty response text returned from model',
          fallbackUsed: true,
        });
        return null;
      }

      // Parse the JSON response (strip markdown fences if model forgot to use responseMimeType)
      const cleaned = rawText.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
      const parsed = JSON.parse(cleaned) as {
        why_suspicious?: string;
        scam_type?: ExplanationScamType;
        actionable_advice?: string[];
        uncertainty_notes?: ExplanationUncertainty;
        summary?: string;
      };

      // Validate required fields exist before using
      if (!parsed.why_suspicious || !parsed.scam_type || !parsed.uncertainty_notes) {
        metricsCollector.recordAiCall(Date.now() - startTime, false, true);
        logger.trackAiFailure({
          scanId: ctx.scanId,
          provider: 'Google Gemini',
          error: `Missing required schema fields: ${Object.keys(parsed).join(', ')}`,
          fallbackUsed: true,
        });
        return null;
      }

      const duration = Date.now() - startTime;
      geminiCircuitBreaker.recordSuccess();
      metricsCollector.recordAiCall(duration, false);

      logger.info('Gemini AI explanation generated successfully', {
        signalCount: brief.signal_count,
        riskScore: brief.risk_score,
        durationMs: duration,
        isUncertain: parsed.uncertainty_notes?.is_uncertain,
        model: config.geminiModel,
      });

      const explanationResult: Partial<AiStructuredExplanation> = {
        why_suspicious: parsed.why_suspicious,
        scam_type: parsed.scam_type,
        actionable_advice: parsed.actionable_advice ?? [],
        uncertainty_notes: parsed.uncertainty_notes,
        summary: parsed.summary ?? '',
        generated_by: 'ai_model' as const,
        ai_generated: true,
      };

      // Save in LRU cache for subsequent duplicate evidence briefs
      this.cache.set(cacheKey, explanationResult);

      return explanationResult;
    } catch (err) {
      const isTimeout = (err as Error).name === 'AbortError';
      geminiCircuitBreaker.recordFailure((err as Error).message);
      metricsCollector.recordAiCall(Date.now() - startTime, false, true);
      logger.trackAiFailure({
        scanId: ctx.scanId,
        provider: 'Google Gemini',
        error: isTimeout ? `Request timed out after ${config.geminiTimeoutMs}ms` : (err as Error).message,
        fallbackUsed: true,
      });
      return null;
    }
  }
}

export const geminiExplainer = new GeminiExplainer();
