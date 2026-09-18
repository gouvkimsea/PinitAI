import { config } from '../../config';
import { logger } from '../../utils/logger';
import { LruCache } from '../../utils/lruCache';
import {
  HybridEvidencePacket,
  StructuredAiAnalysis,
} from './hybridTypes';
import { promptProtection } from './promptProtection';
import { aiResponseValidator } from './aiResponseValidator';
import crypto from 'crypto';

export class AiSemanticAnalyzer {
  private static instance: AiSemanticAnalyzer | null = null;
  private readonly GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta';
  private cache = new LruCache<string, StructuredAiAnalysis>({ maxSize: 500, defaultTtlMs: 3600_000 });

  private constructor() {}

  public static getInstance(): AiSemanticAnalyzer {
    if (!AiSemanticAnalyzer.instance) {
      AiSemanticAnalyzer.instance = new AiSemanticAnalyzer();
    }
    return AiSemanticAnalyzer.instance;
  }

  /**
   * Performs hybrid semantic analysis combining deterministic evidence with LLM reasoning.
   */
  public async analyze(evidencePacket: HybridEvidencePacket): Promise<StructuredAiAnalysis> {
    // 1. Sanitize user input and screen for prompt injection
    const sanitization = promptProtection.sanitizeInput(evidencePacket.rawInputSnippet);
    evidencePacket.sanitizedInput = sanitization.sanitizedContent;

    const cacheKey = crypto
      .createHash('sha256')
      .update(
        JSON.stringify({
          text: sanitization.sanitizedContent,
          rules: evidencePacket.ruleSignals.triggeredRules.map((r) => r.ruleId),
          intel: evidencePacket.threatIntelSignals,
          url: evidencePacket.urlSignals,
        })
      )
      .digest('hex');

    const cached = this.cache.get(cacheKey);
    if (cached) {
      return cached;
    }

    let analysisResult: StructuredAiAnalysis | null = null;

    // 2. Attempt LLM Semantic Analysis if Gemini API Key is configured
    if (config.geminiApiKey) {
      try {
        analysisResult = await this.callGeminiSemanticAnalysis(evidencePacket, sanitization.injectionDetected);
      } catch (err) {
        logger.warn('LLM semantic analysis failed or timed out — using deterministic semantic engine fallback', {
          error: (err as Error).message,
        });
        analysisResult = null;
      }
    }

    // 3. Fallback: Deterministic Semantic Heuristics Engine
    if (!analysisResult) {
      analysisResult = this.deterministicSemanticFallback(evidencePacket, sanitization.injectionDetected);
    }

    if (sanitization.injectionDetected) {
      analysisResult.grounding.sanitized_prompt_injection = true;
      if (!analysisResult.indicators.includes('Adversarial prompt injection attempt detected in input payload')) {
        analysisResult.indicators.unshift('Adversarial prompt injection attempt detected in input payload');
      }
    }

    this.cache.set(cacheKey, analysisResult);
    return analysisResult;
  }

  /**
   * Calls Google Gemini with structured evidence and explicit instructions covering the 12 dimensions.
   */
  private async callGeminiSemanticAnalysis(
    packet: HybridEvidencePacket,
    injectionDetected: boolean
  ): Promise<StructuredAiAnalysis | null> {
    const apiKey = config.geminiApiKey;
    if (!apiKey) return null;

    const systemPrompt = `You are an expert AI security analyst evaluating suspicious messages and URLs.
Your job is to analyze the context, intent, manipulation tactics, and threat signals without hallucination.

EVIDENCE INTEGRITY CONSTRAINTS:
1. You MUST reference ONLY authentic signals provided in the structured evidence packet. Never invent URLs or threat intel feeds.
2. If evidence is ambiguous, incomplete, or from an unknown sender without overt malice, set dimensions.ambiguity.is_ambiguous = true and uncertainty.is_uncertain = true.
3. NEVER expose chain-of-thought, internal deliberation, or <thinking> tags. Output ONLY concise, user-safe evidence.
4. Respond with valid JSON matching the schema exactly.

OUTPUT SCHEMA (respond in valid JSON):
{
  "classification": "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN",
  "confidence": number (0-100),
  "categories": ["string"],
  "indicators": ["string"],
  "reasoning_summary": "string",
  "recommended_action": "string",
  "dimensions": {
    "intent": "string",
    "context": "string",
    "manipulation_tactics": ["string"],
    "impersonation": {
      "detected": boolean,
      "target": "string",
      "type": "bank" | "government" | "executive" | "support" | "brand" | "other",
      "confidence": number (0-100)
    },
    "financial_requests": {
      "detected": boolean,
      "method": "string",
      "amount": "string",
      "currency": "string"
    },
    "credential_requests": {
      "detected": boolean,
      "type": "string"
    },
    "urgency": {
      "level": "none" | "low" | "medium" | "high" | "extreme",
      "timeframe_claimed": "string",
      "reason": "string"
    },
    "threats": ["string"],
    "suspicious_instructions": ["string"],
    "social_engineering_patterns": ["string"],
    "scam_category": "string",
    "ambiguity": {
      "is_ambiguous": boolean,
      "reason": "string",
      "missing_information": ["string"]
    }
  },
  "uncertainty": {
    "is_uncertain": boolean,
    "confidence_level": "very_low" | "low" | "medium" | "high" | "verified",
    "missing_evidence": ["string"]
  }
}`;

    const rulesSnippet = packet.ruleSignals.triggeredRules.length > 0
      ? packet.ruleSignals.triggeredRules.map((r) => `  - [${r.severity}] ${r.ruleId}: ${r.description}`).join('\n')
      : '  (none)';

    const userPrompt = `ANALYZE THIS SECURITY EVIDENCE PACKET:

PRE-GATHERED DETERMINISTIC SIGNALS:
- Target Type: ${packet.targetType}
- Language: ${packet.detectedLanguage || 'en'}
- Extracted Authentic URLs: ${packet.extractedUrls.join(', ') || 'none'}
- Triggered Detection Rules:
${rulesSnippet}
- Threat Intelligence: known_malicious=${packet.threatIntelSignals.knownMalicious}, feeds=${packet.threatIntelSignals.listedOnFeeds.join(', ') || 'none'}
- Preliminary Score: ${packet.deterministicBaseline.preliminaryScore}/100 (${packet.deterministicBaseline.preliminarySeverity})
${injectionDetected ? '- WARNING: Adversarial prompt injection signature was detected in the payload' : ''}

TARGET CONTENT:
${promptProtection.wrapUntrustedContent(packet.sanitizedInput)}

Evaluate all 12 semantic dimensions now and return the validated JSON.`;

    const requestBody = {
      system_instruction: { parts: [{ text: systemPrompt }] },
      contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
      generationConfig: {
        temperature: 0.1,
        topP: 0.8,
        maxOutputTokens: 1500,
        responseMimeType: 'application/json',
      },
    };

    const url = `${this.GEMINI_API_BASE}/models/${config.geminiModel}:generateContent?key=${apiKey}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.geminiTimeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        return null;
      }

      const responseData = await response.json() as any;
      const rawText = responseData?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) return null;

      const rawParsed = aiResponseValidator.parseRawText(rawText);
      return aiResponseValidator.validateAndHarden(rawParsed, packet);
    } catch {
      clearTimeout(timer);
      return null;
    }
  }

  /**
   * Deterministic Semantic Engine Fallback.
   * Accurately analyzes all 12 dimensions when live LLM is offline, unconfigured, or timed out.
   */
  public deterministicSemanticFallback(
    packet: HybridEvidencePacket,
    injectionDetected: boolean
  ): StructuredAiAnalysis {
    const text = (packet.sanitizedInput || '').toLowerCase();
    const triggeredRules = packet.ruleSignals.triggeredRules;

    // 1. Intent Analysis
    let intent = 'Informational message or clean communication';
    if (/verify.*(?:account|identity)|login.*(?:credentials|details)|confirm.*password/i.test(text)) {
      intent = 'Credential or account credential harvesting';
    } else if (/otp|verification code|one-time code|sms code/i.test(text)) {
      intent = 'Two-factor authentication or OTP theft';
    } else if (/pay|fee|deposit|gift card|transfer|crypto|wire/i.test(text)) {
      intent = 'Financial fund extraction or fraudulent payment demand';
    } else if (/download|install|exe|macro|anydesk|teamviewer/i.test(text)) {
      intent = 'Malware installation or unauthorized remote machine control';
    } else if (/won|prize|lottery|winner|claim.*reward/i.test(text)) {
      intent = 'Advance fee lottery or prize scam lure';
    }

    // 2. Context Analysis
    const context = packet.targetType === 'URL'
      ? `Web portal or redirection link (${packet.extractedUrls[0] || 'unspecified'})`
      : 'Direct electronic messaging or communication channel';

    // 3. Manipulation Tactics
    const tactics: string[] = [];
    if (/urgent|immediately|within (?:5|10|15|24)|hours?|minutes?|asap/i.test(text)) {
      tactics.push('artificial_time_urgency');
    }
    if (/arrest|legal action|court|prosecution|police|suspended|locked/i.test(text)) {
      tactics.push('intimidation_and_fear');
    }
    if (/congratulations|lucky|free|reward|100% returns|guaranteed/i.test(text)) {
      tactics.push('greed_and_false_reward');
    }
    if (/confidential|do not tell|keep secret|do not hang up/i.test(text)) {
      tactics.push('victim_isolation');
    }
    if (injectionDetected) {
      tactics.push('adversarial_prompt_injection');
    }

    // 4. Impersonation
    let impersonationDetected = packet.behavioralSignals.impersonationDetected;
    let targetEntity = packet.behavioralSignals.impersonatedEntity;
    let impType: 'bank' | 'government' | 'executive' | 'support' | 'brand' | 'other' | undefined;

    if (/aba bank|acleda|wells fargo|chase|paypal|bank/i.test(text)) {
      impersonationDetected = true;
      targetEntity = targetEntity || 'Financial Institution / Bank';
      impType = 'bank';
    } else if (/police|irs|fbi|ministry|court|subpoena/i.test(text)) {
      impersonationDetected = true;
      targetEntity = targetEntity || 'Law Enforcement or Government Agency';
      impType = 'government';
    } else if (/microsoft support|apple support|technical support/i.test(text)) {
      impersonationDetected = true;
      targetEntity = targetEntity || 'Tech Support Helpdesk';
      impType = 'support';
    }

    // 5. Financial Requests
    const hasFinancial = /pay|fee|deposit|gift card|crypto|wire transfer|western union|zelle/i.test(text);
    let finMethod: string | undefined;
    if (/gift card/i.test(text)) finMethod = 'gift_card';
    else if (/crypto|btc|eth|usdt/i.test(text)) finMethod = 'cryptocurrency';
    else if (/wire transfer|western union/i.test(text)) finMethod = 'wire_transfer';
    else if (/fee|deposit/i.test(text)) finMethod = 'advance_deposit';

    // 6. Credential Requests
    const hasCredentials = /password|pin code|atm pin|otp|seed phrase|recovery phrase/i.test(text);
    let credType: string | undefined;
    if (/otp|verification code/i.test(text)) credType = 'one_time_password';
    else if (/seed phrase|recovery phrase/i.test(text)) credType = 'crypto_seed_phrase';
    else if (/password|pin/i.test(text)) credType = 'account_password';

    // 7. Urgency
    let urgencyLevel: 'none' | 'low' | 'medium' | 'high' | 'extreme' = 'none';
    if (/within (?:5|10|15) minutes|immediately or face arrest/i.test(text)) {
      urgencyLevel = 'extreme';
    } else if (/urgent|immediately|within 24 hours/i.test(text)) {
      urgencyLevel = 'high';
    } else if (/soon|today|reminder/i.test(text)) {
      urgencyLevel = 'medium';
    }

    // 8. Threats
    const threats: string[] = [];
    if (
      /(?:account (?:will be )?permanently (?:deleted|suspended|locked)|permanent(?:ly)? account (?:termination|suspension|closure)|account (?:is )?suspended)/i.test(
        text
      )
    ) {
      threats.push('permanent_account_termination');
    }
    if (/arrest|prosecution|legal action|warrant/i.test(text)) {
      threats.push('legal_arrest_and_police_action');
    }

    // 9. Suspicious Instructions
    const instructions: string[] = [];
    if (/click (?:here|the link)|follow the link/i.test(text)) instructions.push('click_unverified_link');
    if (/send.*(?:code|otp|password)/i.test(text)) instructions.push('forward_security_credentials');
    if (/install.*(?:anydesk|teamviewer|setup\.exe)/i.test(text)) instructions.push('install_remote_access_software');
    if (/scan.*qr/i.test(text)) instructions.push('scan_unverified_qr_code');

    // 10. Social Engineering Patterns
    const socialPatterns: string[] = [];
    if (impersonationDetected) socialPatterns.push('authority_impersonation');
    if (tactics.includes('artificial_time_urgency')) socialPatterns.push('artificial_scarcity_or_urgency');
    if (hasFinancial) socialPatterns.push('advance_fee_or_payment_diversion');
    if (hasCredentials) socialPatterns.push('credential_harvesting');

    // 11. Scam Category
    let scamCategory = 'general_content';
    if (triggeredRules.length > 0) {
      scamCategory = String(triggeredRules[0].category);
    } else if (hasCredentials) {
      scamCategory = credType === 'one_time_password' ? 'otp_theft' : 'credential_theft';
    } else if (hasFinancial) {
      scamCategory = finMethod === 'gift_card' ? 'payment_fraud' : 'financial_fraud';
    } else if (impersonationDetected) {
      scamCategory = 'impersonation';
    }

    // 12. Ambiguity & Uncertainty
    const isShort = text.length < 30;
    const hasFewSignals = tactics.length === 0 && !hasFinancial && !hasCredentials && !impersonationDetected;
    const isAmbiguous = isShort || (hasFewSignals && !packet.threatIntelSignals.knownMalicious);

    const categories = Array.from(
      new Set([scamCategory, ...triggeredRules.map((r) => String(r.category))])
    );

    const indicators: string[] = [
      ...triggeredRules.map((r) => `[${r.ruleId}] ${r.description}`),
      ...tactics.map((t) => `Manipulation tactic: ${t}`),
      ...threats.map((th) => `Coercive threat: ${th}`),
    ];

    if (hasCredentials) indicators.push(`Solicitation of sensitive authentication credentials (${credType})`);
    if (hasFinancial) indicators.push(`Financial transaction request detected (${finMethod || 'unspecified'})`);

    let classification: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN' = 'CLEAN';
    let confidence = 85;

    if (packet.threatIntelSignals.knownMalicious || triggeredRules.some((r) => r.severity === 'critical') || (hasCredentials && impersonationDetected)) {
      classification = 'MALICIOUS';
      confidence = 90;
    } else if (indicators.length >= 2 || hasFinancial || hasCredentials || urgencyLevel === 'high') {
      classification = 'SUSPICIOUS';
      confidence = 75;
    } else if (isAmbiguous) {
      classification = 'UNKNOWN';
      confidence = 45;
    }

    const reasoningSummary = classification === 'MALICIOUS'
      ? `High-risk scam identified. The communication demonstrates ${intent.toLowerCase()} accompanied by ${tactics.join(', ') || 'deceptive techniques'}.`
      : classification === 'SUSPICIOUS'
      ? `Suspicious markers observed. Contains ${intent.toLowerCase()} with potential deception risk.`
      : isAmbiguous
      ? `Content contains limited or ambiguous context. No confirmed fraud signatures detected, but exercise caution.`
      : `No deceptive social engineering, credential harvesting, or threat patterns detected.`;

    const recommendedAction = classification === 'MALICIOUS'
      ? 'Do not engage, click links, or send credentials. Block the sender.'
      : classification === 'SUSPICIOUS'
      ? 'Verify sender identity independently through official phone numbers or websites.'
      : 'Standard caution applies.';

    return {
      classification,
      confidence,
      categories,
      indicators,
      reasoning_summary: reasoningSummary,
      recommended_action: recommendedAction,
      dimensions: {
        intent,
        context,
        manipulation_tactics: tactics,
        impersonation: {
          detected: impersonationDetected,
          target: targetEntity,
          type: impType,
          confidence: impersonationDetected ? 80 : 0,
        },
        financial_requests: {
          detected: hasFinancial,
          method: finMethod,
        },
        credential_requests: {
          detected: hasCredentials,
          type: credType,
        },
        urgency: {
          level: urgencyLevel,
        },
        threats,
        suspicious_instructions: instructions,
        social_engineering_patterns: socialPatterns,
        scam_category: scamCategory,
        ambiguity: {
          is_ambiguous: isAmbiguous,
          reason: isAmbiguous ? 'Input has sparse indicators or brief length.' : '',
          missing_information: isAmbiguous ? ['Sender verified identity', 'Communication context'] : [],
        },
      },
      uncertainty: {
        is_uncertain: isAmbiguous,
        confidence_level: isAmbiguous ? 'low' : confidence >= 80 ? 'high' : 'medium',
        missing_evidence: isAmbiguous ? ['Sender verified identity'] : [],
      },
      grounding: {
        url_hallucinations_filtered: 0,
        intel_hallucinations_filtered: 0,
        cot_stripped: false,
        deterministic_override_applied: false,
        sanitized_prompt_injection: injectionDetected,
      },
    };
  }
}

export const aiSemanticAnalyzer = AiSemanticAnalyzer.getInstance();
