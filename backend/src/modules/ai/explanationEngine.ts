import {
  AiStructuredExplanation,
  ExplanationContext,
  ExplanationSignalItem,
  ExplanationScamType,
  ExplanationUncertainty,
} from './types';
import { geminiExplainer } from './geminiExplainer';
import { logger } from '../../utils/logger';


import crypto from 'crypto';
import { LruCache } from '../../utils/lruCache';
import { MetricsCollector } from '../monitoring/metricsCollector';

export interface ExplanationResult {
  summary: string;
  aiExplanation: string;
  recommendedActions: string[];
  safeFactors: string[];
}

export class ExplanationEngine {
  private readonly ENGINE_VERSION = '2.1.0-grounded';
  private explanationCache = new LruCache<string, AiStructuredExplanation>({ maxSize: 1000, defaultTtlMs: 3600_000 });

  /**
   * Generates a fully structured 5-part AI explanation strictly grounded in deterministic evidence.
   *
   * Pipeline:
   * 1. Check in-memory explanation LRU cache for identical brief (0ms fast path)
   * 2. Always run the deterministic rules engine to extract verified signals (ground truth)
   * 3. Attempt Gemini LLM call with structured evidence brief (never raw user content)
   * 4. If LLM succeeds: replace narrative fields with AI output, keep all grounding metadata
   * 5. If LLM fails/unavailable: use rules engine output entirely
   *
   * Never fabricates evidence. Explicitly highlights uncertainty when evidence is insufficient.
   */
  async generateStructuredExplanation(ctx: ExplanationContext): Promise<AiStructuredExplanation> {
    const startTime = Date.now();
    const metricsCollector = MetricsCollector.getInstance();

    const cacheKey = crypto
      .createHash('sha256')
      .update(
        JSON.stringify({
          targetType: ctx.targetType,
          threatCategory: ctx.threatCategory,
          riskScore: ctx.riskScore,
          classification: ctx.classification,
          threatLevel: ctx.threatLevel,
          confidenceScore: ctx.confidenceScore,
          language: ctx.language,
          indicators: ctx.indicators,
          rawContentSnippet: ctx.rawContentSnippet,
        })
      )
      .digest('hex');

    const cached = this.explanationCache.get(cacheKey);
    if (cached) {
      metricsCollector.recordAiCall(0, true);
      return cached;
    }

    const isKm = ctx.language === 'km' || ctx.language === 'km-en';

    // ── STEP 1: Deterministic extraction (always runs, never skipped) ─────────────────────
    const verifiedSignals = this.extractVerifiedSignals(ctx);
    const deterministicScamType = this.resolveScamType(ctx, isKm);
    const deterministicUncertainty = this.evaluateUncertainty(ctx, verifiedSignals, isKm);
    const deterministicWhySuspicious = this.generateWhySuspicious(ctx, verifiedSignals, isKm);
    const deterministicAdvice = this.generateActionableAdvice(ctx, isKm);
    const deterministicSummary = this.generateSummary(ctx, isKm);
    const safeFactors = this.generateSafeFactors(ctx, isKm);

    // Grounding metadata — always from deterministic engine, never overridden by LLM
    const groundingMetadata = {
      grounded_in_evidence: true,
      evidence_summary: `Verified ${verifiedSignals.length} telemetry signals across ${ctx.detectorResults?.length || 1} detectors.`,
      verified_signal_count: verifiedSignals.length,
      unverified_claims_filtered: 0,
    };

    // ── STEP 2: Attempt Gemini LLM explanation (Optimization 14: Limit AI calls when deterministic evidence is conclusive)
    let aiResult: Partial<AiStructuredExplanation> | null = null;

    const isConclusiveClean = ctx.threatLevel === 'SAFE' && (!ctx.indicators || ctx.indicators.length === 0) && (ctx.confidenceScore ?? 0) >= 85;
    const isConclusiveMalicious = ((ctx.threatLevel as string) === 'CRITICAL' || ctx.threatLevel === 'MALICIOUS') && (ctx.confidenceScore ?? 0) >= 90 && verifiedSignals.length >= 2;
    const hasConclusiveEvidence = isConclusiveClean || isConclusiveMalicious;

    if (hasConclusiveEvidence && !(ctx as any).forceAiExplanation) {
      metricsCollector.recordAiCall(0, true);
      logger.debug('Deterministic analysis provided conclusive evidence; limiting redundant LLM call', {
        threatLevel: ctx.threatLevel,
        confidenceScore: ctx.confidenceScore,
        signalCount: verifiedSignals.length,
      });
      aiResult = null;
    } else {
      try {
        aiResult = await geminiExplainer.explain(ctx, verifiedSignals);
      } catch (err) {
        // Defensive: geminiExplainer already handles errors internally, but catch any leaks
        logger.warn('Unexpected error from GeminiExplainer — using rules engine fallback', {
          error: (err as Error).message,
        });
        aiResult = null;
      }
    }

    // ── STEP 3: Compose final result ──────────────────────────────────────────────────────
    // If LLM succeeded: use AI narrative fields; keep all deterministic grounding fields
    // If LLM failed:    use purely deterministic output
    if (aiResult) {
      const aiUncertainty = aiResult.uncertainty_notes ?? deterministicUncertainty;
      const aiAdvice = (aiResult.actionable_advice && aiResult.actionable_advice.length > 0)
        ? aiResult.actionable_advice
        : deterministicAdvice;

      const explanation: AiStructuredExplanation = {
        // ── AI-generated narrative fields (LLM output)
        why_suspicious: aiResult.why_suspicious ?? deterministicWhySuspicious,
        scam_type: aiResult.scam_type ?? deterministicScamType,
        actionable_advice: aiAdvice,
        uncertainty_notes: aiUncertainty,
        summary: aiResult.summary ?? deterministicSummary,
        aiExplanation: aiResult.why_suspicious ?? deterministicWhySuspicious,

        // ── Deterministic grounding fields (always from rules engine — never from LLM)
        triggered_signals: verifiedSignals,
        ...groundingMetadata,

        // ── Backward-compatible fields
        recommended_actions: aiAdvice,
        recommendedActions: aiAdvice,
        safe_factors: safeFactors,

        // ── Provenance
        generated_by: 'ai_model',
        ai_generated: true,
        engine_version: this.ENGINE_VERSION,
        timestamp: new Date().toISOString(),
      };
      this.explanationCache.set(cacheKey, explanation);
      metricsCollector.recordAiCall(Date.now() - startTime, false, false);
      return explanation;
    }

    // Pure rules-engine fallback
    const fallbackExplanation: AiStructuredExplanation = {
      why_suspicious: deterministicWhySuspicious,
      triggered_signals: verifiedSignals,
      scam_type: deterministicScamType,
      actionable_advice: deterministicAdvice,
      uncertainty_notes: deterministicUncertainty,
      ...groundingMetadata,
      summary: deterministicSummary,
      aiExplanation: deterministicWhySuspicious,
      recommended_actions: deterministicAdvice,
      recommendedActions: deterministicAdvice,
      safe_factors: safeFactors,
      generated_by: 'grounded_rules_engine',
      ai_generated: false,
      engine_version: this.ENGINE_VERSION,
      timestamp: new Date().toISOString(),
    };

    this.explanationCache.set(cacheKey, fallbackExplanation);
    metricsCollector.recordAiCall(Date.now() - startTime, false, true);
    return fallbackExplanation;
  }


  /**
   * Synchronous / backward-compatible method conforming to existing callers.
   */
  generateExplanation(ctx: ExplanationContext): ExplanationResult {
    const isKm = ctx.language === 'km' || ctx.language === 'km-en';

    const signals = this.extractVerifiedSignals(ctx);
    const why = this.generateWhySuspicious(ctx, signals, isKm);
    const summary = this.generateSummary(ctx, isKm);
    const recommendedActions = this.generateActionableAdvice(ctx, isKm);
    const safeFactors = this.generateSafeFactors(ctx, isKm);

    return {
      summary,
      aiExplanation: why,
      recommendedActions,
      safeFactors,
    };
  }

  /**
   * Extracts only verified signals directly from detector results without fabricating.
   */
  private extractVerifiedSignals(ctx: ExplanationContext): ExplanationSignalItem[] {
    const signals: ExplanationSignalItem[] = [];
    const seen = new Set<string>();

    if (ctx.detectorResults && ctx.detectorResults.length > 0) {
      for (const det of ctx.detectorResults) {
        if (det.score > 0 || (det.evidence.indicators && det.evidence.indicators.length > 0)) {
          const indicators = det.evidence.indicators || [];
          if (indicators.length === 0 && det.evidence.summary) {
            const key = `${det.detector_name}-${det.evidence.summary}`;
            if (!seen.has(key)) {
              seen.add(key);
              signals.push({
                signal: det.evidence.summary,
                detail: `Detector '${det.detector_name}' recorded threat score of ${det.score}/100.`,
                severity: det.severity === 'critical' ? 'critical' : det.severity === 'high' ? 'high' : 'medium',
                source_detector: det.detector_name,
              });
            }
          } else {
            for (const ind of indicators) {
              const key = `${det.detector_name}-${ind}`;
              if (!seen.has(key)) {
                seen.add(key);
                signals.push({
                  signal: ind,
                  detail: det.evidence.summary || `Observed indicator '${ind}' during ${det.detector_name} evaluation.`,
                  severity: det.severity === 'critical' ? 'critical' : det.severity === 'high' ? 'high' : 'medium',
                  source_detector: det.detector_name,
                });
              }
            }
          }
        }
      }
    }

    // Include indicators array if not already present
    if (ctx.indicators && ctx.indicators.length > 0) {
      for (const ind of ctx.indicators) {
        const alreadyIncluded = signals.some((s) => s.signal.toLowerCase() === ind.toLowerCase());
        if (!alreadyIncluded) {
          signals.push({
            signal: ind,
            detail: `Security engine flagged indicator: ${ind}`,
            severity: ctx.riskScore >= 80 ? 'critical' : ctx.riskScore >= 60 ? 'high' : 'medium',
            source_detector: 'multi_layer_pipeline',
          });
        }
      }
    }

    return signals;
  }

  /**
   * Resolves the real-world scam type, threat category, and modus operandi.
   */
  private resolveScamType(ctx: ExplanationContext, isKm: boolean): ExplanationScamType {
    const rawCategory = (ctx.threatCategory || 'UNKNOWN').toLowerCase();
    const score = ctx.riskScore ?? 0;

    let category = 'general_threat';
    let name = isKm ? 'ការគំរាមកំហែងទូទៅ' : 'General Deceptive Threat';
    let description = isKm
      ? 'ខ្លឹមសារមានផ្ទុកសញ្ញាសម្គាល់មិនប្រក្រតីដែលតម្រូវឱ្យមានការផ្ទៀងផ្ទាត់។'
      : 'Content exhibits anomalous or deceptive attributes that require independent verification.';

    if (score < 20) {
      category = 'safe_content';
      name = isKm ? 'ការប្រាស្រ័យទាក់ទងធម្មតា (សុវត្ថិភាព)' : 'Standard Legitimate Communication';
      description = isKm
        ? 'មិនមានល្បិចបោកប្រាស់ ឬការគំរាមកំហែងសុវត្ថិភាពច្បាស់លាស់ត្រូវបានរកឃើញឡើយ។'
        : 'The content conforms to normal benign communication without deceptive patterns or indicators.';
    } else if (rawCategory.includes('phish') || rawCategory.includes('credential')) {
      category = 'phishing';
      name = isKm ? 'ការក្លែងបន្លំលួចគណនី (Phishing)' : 'Credential Phishing Attack';
      description = isKm
        ? 'ជនខិលខូចបង្កើតសារ ឬតំណភ្ជាប់ក្លែងក្លាយដើម្បីបន្លំលួចយកពាក្យសម្ងាត់ ឬព័ត៌មានធនាគាររបស់អ្នក។'
        : 'Perpetrators craft spoofed messages or counterfeit portals designed to harvest authentication credentials and banking data.';
    } else if (rawCategory.includes('otp') || rawCategory.includes('takeover')) {
      category = 'account_takeover';
      name = isKm ? 'ការប៉ុនប៉ងលួចគ្រប់គ្រងគណនី (Account Takeover / OTP)' : 'Account Takeover / OTP Interception';
      description = isKm
        ? 'ការទាមទារលេខកូដសម្ងាត់ OTP ឬពាក្យសម្ងាត់ដើម្បីចូលបញ្ជាគណនីធនាគារ ឬបណ្តាញសង្គមរបស់អ្នក។'
        : 'Attackers pressure victims to surrender multi-factor one-time passwords (OTPs) to gain unauthorized access to accounts.';
    } else if (rawCategory.includes('invest')) {
      category = 'fake_investment';
      name = isKm ? 'ការបោកប្រាស់វិនិយោគក្លែងក្លាយ' : 'High-Yield Investment Fraud (Ponzi / Pig Butchering)';
      description = isKm
        ? 'សន្យាផ្តល់ផលចំណេញខ្ពស់មិនសមហេតុផល ឬគ្មានហានិភ័យ ដើម្បីទាក់ទាញឱ្យផ្ញើប្រាក់។'
        : 'Fraudsters entice victims with promises of guaranteed, unrealistic high returns before freezing funds or demanding exit taxes.';
    } else if (rawCategory.includes('job') || rawCategory.includes('task')) {
      category = 'fake_job';
      name = isKm ? 'ការងារក្លែងក្លាយតាមអនឡាញ' : 'Employment / Task Fee Scam';
      description = isKm
        ? 'ផ្តល់ការងារងាយស្រួលប្រាក់ខែខ្ពស់ ប៉ុន្តែតម្រូវឱ្យបង់ប្រាក់កក់ ឬទិញកិច្ចការជាមុន។'
        : 'Scammers offer high-paying tasks (e.g. rating videos) but demand upfront deposits or upgrade fees to release earnings.';
    } else if (rawCategory.includes('impersonat')) {
      category = 'impersonation';
      name = isKm ? 'ការក្លែងបន្លំអត្តសញ្ញាណស្ថាប័ន' : 'Brand or Authority Impersonation';
      description = isKm
        ? 'ក្លែងបន្លំជាធនាគារ សមត្ថកិច្ច ឬក្រុមហ៊ុនល្បីឈ្មោះ ដើម្បីបង្កើតការជឿទុកចិត្ត ឬការភ័យខ្លាច។'
        : 'Deceptive actors spoof official institutions (banks, law enforcement, utility brands) to coerce victims into compliance.';
    } else if (rawCategory.includes('payment') || rawCategory.includes('advance')) {
      category = 'payment_scam';
      name = isKm ? 'ការបោកប្រាស់ទាក់ទងនឹងការទូទាត់ប្រាក់' : 'Advance-Fee / Overpayment Scam';
      description = isKm
        ? 'ល្បិចទាមទារឱ្យផ្ទេរប្រាក់ជាមុន ឬក្លែងបន្លំវិក្កយបត្រផ្ទេរប្រាក់លើស។'
        : 'Tricks involving fraudulent payment receipts, accidental overpayment refund demands, or untraceable payment methods.';
    } else if (rawCategory.includes('malware') || rawCategory.includes('executable') || ctx.targetType === 'FILE') {
      category = 'malware_hazard';
      name = isKm ? 'ឯកសារមេរោគ ឬកូដគ្រោះថ្នាក់' : 'Malicious File / Executable Hazard';
      description = isKm
        ? 'ឯកសារមានផ្ទុកកូដ ឬទម្រង់គ្រោះថ្នាក់ដែលអាចដំណើរការដើម្បីគ្រប់គ្រងឧបករណ៍របស់អ្នក។'
        : 'The uploaded file contains executable headers, suspicious scripts, or disguised extensions engineered to compromise the endpoint.';
    }

    return {
      category,
      name,
      description,
      threat_level: score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'SUSPICIOUS' : 'LOW',
    };
  }

  /**
   * Generates a grounded explanation of WHY the content is suspicious (or clean).
   */
  private generateWhySuspicious(
    ctx: ExplanationContext,
    signals: ExplanationSignalItem[],
    isKm: boolean
  ): string {
    const score = ctx.riskScore ?? 0;

    if (score < 20) {
      return isKm
        ? 'ខ្លឹមសារនេះមិនមានសញ្ញាគួរឱ្យសង្ស័យឡើយ។ ការវិភាគស៊ីជម្រៅមិនបានរកឃើញល្បិចបង្កើតការភ័យស្លន់ស្លោ ការទាមទារលេខសម្ងាត់ ឬតំណភ្ជាប់ក្លែងបន្លំណាមួយនោះទេ។'
        : 'This content demonstrates standard, non-malicious characteristics. Multi-layer deterministic analysis detected no coercive urgency, credential harvesting, unauthorized banking requests, or malicious payload signatures.';
    }

    if (signals.length === 0) {
      return isKm
        ? 'ខ្លឹមសារនេះត្រូវបានសម្គាល់ថាគួរឱ្យសង្ស័យដោយសារទម្រង់ ឬបរិបទមិនប្រក្រតី ប៉ុន្តែមិនទាន់មានភស្តុតាងច្បាស់លាស់បញ្ជាក់ពីប្រភេទនៃការបោកប្រាស់នៅឡើយទេ។'
        : 'The target was flagged with elevated caution due to structural or contextual anomalies, though specific threat signatures remain limited.';
    }

    const signalNames = signals.slice(0, 3).map((s) => s.signal).join(', ');

    if (score >= 60) {
      return isKm
        ? `ខ្លឹមសារនេះមានហានិភ័យខ្ពស់ ដោយសារបានរកឃើញសញ្ញាគ្រោះថ្នាក់ច្បាស់លាស់រួមមាន៖ ${signalNames}។ យុទ្ធសាស្ត្រនេះត្រូវគ្នានឹងល្បិចបោកប្រាស់តាមប្រព័ន្ធបច្ចេកវិទ្យា ដើម្បីបន្លំយកប្រាក់ ឬទិន្នន័យសម្ងាត់របស់អ្នក។`
        : `This content presents a high security risk based on verified threat indicators: ${signalNames}. The tactics detected correlate directly with social engineering, deliberate deceptive misdirection, or unauthorized credential access.`;
    }

    return isKm
      ? `ការវិភាគបានរកឃើញចំណុចមិនប្រក្រតីមួយចំនួន (${signalNames}) ដែលបង្ហាញពីលទ្ធភាពនៃការក្លែងបន្លំ ឬការលាក់បាំងព័ត៌មានពិត។`
      : `Deterministic analysis flagged elevated anomalies including ${signalNames}. While not conclusively malicious, these signals frequently accompany deceptive lures and warrant strict scrutiny.`;
  }

  /**
   * Formulates actionable, practical protective advice for the end-user.
   */
  private generateActionableAdvice(ctx: ExplanationContext, isKm: boolean): string[] {
    const score = ctx.riskScore ?? 0;
    const category = (ctx.threatCategory || '').toLowerCase();
    const advice: string[] = [];

    if (score < 20) {
      advice.push(
        isKm ? 'បន្តដោយប្រុងប្រយ័ត្នជាធម្មតា' : 'Proceed with standard caution.',
        isKm ? 'ផ្ទៀងផ្ទាត់តាមឆានែលផ្លូវការ ប្រសិនបើមានការស្នើសុំប្រាក់ ឬទិន្នន័យផ្ទាល់ខ្លួននាពេលអនាគត' : 'Always verify unexpected requests for funds or personal data through verified channels.'
      );
      return advice;
    }

    if (category.includes('otp') || category.includes('takeover') || category.includes('phish')) {
      advice.push(
        isKm ? 'ហាមផ្ញើលេខកូដសម្ងាត់ (OTP) ឬពាក្យសម្ងាត់ឱ្យអ្នកដទៃដាច់ខាត ទោះបីជាគេអះអាងថាជាបុគ្គលិកធនាគារក៏ដោយ' : 'NEVER share one-time passwords (OTP) or authentication codes with anyone, including individuals claiming to represent your bank.',
        isKm ? 'ហាមចុចលើតំណភ្ជាប់ ឬបំពេញព័ត៌មានក្នុងទម្រង់ដែលបានផ្ញើមក' : 'Do NOT click any embedded links, download files, or submit login credentials on the referenced page.',
        isKm ? 'ទាក់ទងទៅកាន់ធនាគារ ឬស្ថាប័នពាក់ព័ន្ធតាមលេខទូរស័ព្ទផ្លូវការដែលអ្នកស្គាល់' : 'Contact the official institution directly using verified contact information from your physical card or official website.'
      );
    } else if (ctx.targetType === 'FILE' || category.includes('malware')) {
      advice.push(
        isKm ? 'ហាមបើក ឬដំណើរការ (Run) ឯកសារនេះនៅលើកុំព្យូទ័រ ឬទូរស័ព្ទរបស់អ្នក' : 'Do NOT open, run, or execute this file. It has been quarantined for safety.',
        isKm ? 'លុបឯកសារនេះចោលភ្លាមៗ' : 'Delete or isolate the file immediately to avoid accidental execution.',
        isKm ? 'ដំណើរការកម្មវិធីស្កេនមេរោគ (Antivirus) លើឧបករណ៍របស់អ្នក' : 'Perform a full system scan with up-to-date endpoint protection software.'
      );
    } else if (category.includes('invest') || category.includes('crypto')) {
      advice.push(
        isKm ? 'ហាមផ្ទេរប្រាក់ ឬរូបិយប័ណ្ណគ្រីបតូទៅកាន់គណនីដែលគេបានណែនាំ' : 'Do NOT transfer money or cryptocurrency to the specified addresses.',
        isKm ? 'ចងចាំថា ការសន្យាផ្តល់ផលចំណេញខ្ពស់ដោយគ្មានហានិភ័យគឺជាការបោកប្រាស់' : 'Remember that guaranteed, risk-free high profits are hallmark signs of investment fraud.'
      );
    } else {
      advice.push(
        isKm ? 'ហាមឆ្លើយតប ឬផ្ទេរប្រាក់តាមការទាមទារ' : 'Do NOT respond, comply with payment requests, or provide sensitive information.',
        isKm ? 'ផ្ទៀងផ្ទាត់អត្តសញ្ញាណរបស់អ្នកផ្ញើដោយផ្ទាល់តាមរយៈលេខទូរស័ព្ទផ្លូវការ' : 'Verify the sender identity independently through an established, out-of-band communication channel.',
        isKm ? 'រាយការណ៍សារ ឬគណនីនេះទៅកាន់ផ្នែកសុវត្ថិភាព' : 'Report the message or account to your organization or platform security team.'
      );
    }

    return advice;
  }

  /**
   * Explicitly evaluates and articulates uncertainty and missing information.
   * Required: "If there is insufficient evidence, the AI must explicitly say that the result is uncertain."
   */
  private evaluateUncertainty(
    ctx: ExplanationContext,
    signals: ExplanationSignalItem[],
    isKm: boolean
  ): ExplanationUncertainty {
    const score = ctx.riskScore ?? 0;
    const isClean = score < 20 && signals.length === 0;
    const isAmbiguous = (score >= 20 && score <= 55) || ctx.classification === 'Needs Review';
    const confidenceScore = ctx.confidenceScore ?? 75;

    if (isClean) {
      return {
        is_uncertain: true,
        reason: isKm
          ? 'លទ្ធផលនេះមិនមានភស្តុតាងគ្រប់គ្រាន់ដើម្បីបញ្ជាក់ពីចេតនាអាក្រក់ឡើយ។ ការវិភាគបច្ចេកទេសលើអត្ថបទមិនអាចផ្ទៀងផ្ទាត់អត្តសញ្ញាណពិតរបស់អ្នកផ្ញើនៅខាងក្រៅប្រព័ន្ធបានទេ។'
          : 'Result is uncertain due to insufficient evidence of malicious intent. Static content analysis cannot verify the sender real-world identity or future intentions beyond the submitted text.',
        missing_information: [
          isKm ? 'ការផ្ទៀងផ្ទាត់អត្តសញ្ញាណអ្នកផ្ញើផ្ទាល់' : 'Out-of-band sender identity verification',
          isKm ? 'បរិបទនៃការសន្ទនាទាំងមូលនៅខាងក្រៅ' : 'Broader off-platform conversational context',
        ],
        confidence_level: 'low',
      };
    }

    if (isAmbiguous || signals.length <= 1) {
      return {
        is_uncertain: true,
        reason: isKm
          ? 'ភស្តុតាងដែលទទួលបានមិនទាន់គ្រប់គ្រាន់ដើម្បីសន្និដ្ឋានដាច់ខាត។ សញ្ញាព្រមានខ្លះអាចកើតឡើងដោយចៃដន្យ ឬស្ថិតក្នុងបរិបទស្របច្បាប់។'
          : 'Insufficient deterministic evidence to reach a definitive verdict. Some observed anomalies can occur in legitimate business or conversational contexts.',
        missing_information: [
          isKm ? 'ចេតនាពិតប្រាកដនៃតំណភ្ជាប់ ឬការស្នើសុំ' : 'Destination landing page behavioral history',
          isKm ? 'ប្រវត្តិទំនាក់ទំនងរវាងភាគីទាំងពីរ' : 'Established relationship between parties',
        ],
        confidence_level: 'medium',
      };
    }

    return {
      is_uncertain: false,
      reason: isKm
        ? 'ភស្តុតាងរឹងមាំត្រូវបានបញ្ជាក់ដោយប្រព័ន្ធស្វែងរកសញ្ញាគ្រោះថ្នាក់ជាច្រើនស្របគ្នា។'
        : 'High confidence based on multiple correlated security indicators independently confirming deceptive characteristics.',
      missing_information: [],
      confidence_level: confidenceScore >= 80 ? 'high' : 'medium',
    };
  }

  private generateSummary(ctx: ExplanationContext, isKm: boolean): string {
    const score = ctx.riskScore ?? 0;
    if (score >= 60) {
      return isKm
        ? `ការគំរាមកំហែងកម្រិតខ្ពស់! បានរកឃើញសញ្ញាក្លែងបន្លំច្បាស់លាស់ (${ctx.threatCategory})។`
        : `High Threat Warning! Verified deceptive patterns detected corresponding to ${ctx.threatCategory}.`;
    }
    if (score >= 40) {
      return isKm
        ? `ការប្រុងប្រយ័ត្ន៖ រកឃើញសញ្ញាមិនប្រក្រតីមួយចំនួន (${ctx.threatCategory})។`
        : `Elevated Caution: Anomalies and warning signs identified (${ctx.threatCategory}).`;
    }
    return isKm
      ? 'មិនមានសញ្ញាគួរឱ្យសង្ស័យត្រូវបានរកឃើញទេ។ អាចដំណើរការដោយប្រុងប្រយ័ត្នជាធម្មតា។'
      : 'No suspicious indicators were identified. Proceed with standard caution.';
  }

  private generateSafeFactors(ctx: ExplanationContext, isKm: boolean): string[] {
    const score = ctx.riskScore ?? 0;
    const factors: string[] = [];

    if (score < 40) {
      factors.push(
        isKm ? 'គ្មានពាក្យគន្លឹះទាមទារប្រាក់ ឬពាក្យសម្ងាត់' : 'No credential harvesting or high-urgency keywords detected',
        isKm ? 'រចនាសម្ព័ន្ធធម្មតា គ្មានភាពមិនប្រក្រតី' : 'Standard structure without hidden payload anomalies'
      );
    }
    if (ctx.targetType === 'URL' && score < 50) {
      factors.push(isKm ? 'មិនស្ថិតក្នុងបញ្ជីខ្មៅនៃគេហទំព័របោកប្រាស់' : 'Domain is not listed on active threat intelligence blocklists');
    }
    if (ctx.targetType === 'FILE' && score < 50) {
      factors.push(isKm ? 'មិនមានកូដ Executable ឬ Macros គ្រោះថ្នាក់' : 'Zero malicious executable headers or macro exploits identified');
    }

    return factors;
  }
}

export const explanationEngine = new ExplanationEngine();
