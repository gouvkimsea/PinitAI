/**
 * Pinit Dedicated Message Scam Detection Engine
 * Combines normalization, entity extraction, 28 behavioral patterns, intent classification,
 * multi-signal weighted scoring, calibrated confidence, and grounded explainability.
 */

import { messageNormalizer } from './messageNormalizer';
import { entityExtractor, EntityExtractor } from './entityExtractor';
import { behavioralDetector } from './behavioralDetector';
import { intentClassifier } from './intentClassifier';
import {
  MessageScamResult,
  MessageRiskLevel,
  MessageEvidenceItem,
  BehavioralPatternMatch,
  SocialEngineeringAnalysis,
} from './types';

export class MessageScamEngine {
  /**
   * Analyzes an arbitrary user-provided message and returns a comprehensive,
   * fully explainable scam evaluation.
   */
  analyze(rawContent: string): MessageScamResult {
    const startTime = Date.now();

    // 1. Normalization & De-obfuscation Layer
    const normalized = messageNormalizer.normalize(rawContent);

    // If message is completely empty
    if (!normalized.cleaned) {
      return this.buildEmptyResult(startTime);
    }

    // 2. Entity Extraction Layer
    const entities = entityExtractor.extract(normalized.cleaned, normalized.deobfuscated);

    // 3. Behavioral Pattern Detection Layer (All 28 Patterns)
    const patterns = behavioralDetector.detect(normalized.cleaned, normalized.deobfuscated);

    // 4. Intent Classification Layer
    const intent = intentClassifier.classify(patterns, entities, normalized.cleaned);

    // 5. Social Engineering Analysis Layer
    const socialEngineering = this.analyzeSocialEngineering(patterns, entities);

    // 6. Multi-Signal Evidence Construction
    const evidence = this.buildEvidence(patterns, entities, normalized, socialEngineering);

    // 7. Multi-Signal Weighted Scoring & Correlation Amplification
    const { riskScore, rawConfidence, scamCategories } = this.calculateWeightedRiskScore(
      patterns,
      entities,
      normalized,
      socialEngineering
    );

    // 8. Enforce the Anti-Unilateral Principle and Uncertainty Calibration
    const { finalScore, finalRiskLevel, confidence } = this.classifyRiskAndConfidence(
      riskScore,
      rawConfidence,
      patterns,
      entities,
      intent
    );

    // 9. Indicators formulation
    const indicators = evidence.map((e) => `${e.signal}: ${e.details}`);

    // 10. Explanation & Actionable Guidance Generation
    const { explanation, recommendedAction } = this.generateGroundedExplanation(
      finalRiskLevel,
      finalScore,
      scamCategories,
      evidence,
      entities,
      intent,
      normalized.detectedLanguage
    );

    const executionTimeMs = Date.now() - startTime;

    return {
      riskLevel: finalRiskLevel,
      riskScore: finalScore,
      confidence,
      scamCategories,
      indicators,
      extractedEntities: entities,
      behavioralPatterns: patterns,
      intent,
      socialEngineering,
      recommendedAction,
      explanation,
      evidence,
      language: normalized.detectedLanguage,
      normalizedText: normalized.cleaned,
      executionTimeMs,
    };
  }

  /**
   * Evaluates social engineering dimensions
   */
  private analyzeSocialEngineering(
    patterns: BehavioralPatternMatch[],
    entities: any
  ): SocialEngineeringAnalysis {
    const types = new Set(patterns.map((p) => p.patternType));

    let urgencyLevel: 'NONE' | 'MODERATE' | 'SEVERE' = 'NONE';
    if (types.has('EXCESSIVE_URGENCY')) {
      urgencyLevel = 'SEVERE';
    } else if (types.has('URGENCY')) {
      urgencyLevel = 'MODERATE';
    }

    const fearTactics = types.has('THREATS') || types.has('FEAR_BASED_MANIPULATION');
    const authorityClaim =
      types.has('AUTHORITY_IMPERSONATION') ||
      types.has('FAKE_GOVERNMENT_COMMUNICATION') ||
      types.has('FAKE_BANK_COMMUNICATION') ||
      entities.brands.length > 0;

    let manipulationScore = 0;
    if (urgencyLevel === 'SEVERE') manipulationScore += 35;
    else if (urgencyLevel === 'MODERATE') manipulationScore += 20;
    if (fearTactics) manipulationScore += 35;
    if (authorityClaim) manipulationScore += 25;
    if (types.has('ROMANCE_MANIPULATION')) manipulationScore += 20;

    return {
      urgencyLevel,
      fearTactics,
      authorityClaim,
      manipulationScore: Math.min(100, manipulationScore),
    };
  }

  /**
   * Builds an explainable evidence list grounded in verified indicators
   */
  private buildEvidence(
    patterns: BehavioralPatternMatch[],
    entities: any,
    normalized: any,
    _socialEng: SocialEngineeringAnalysis
  ): MessageEvidenceItem[] {
    const evidence: MessageEvidenceItem[] = [];

    // Credential Harvesting Evidence
    for (const cred of entities.requestedCredentials) {
      evidence.push({
        signal: `Requests ${cred}`,
        category: 'CREDENTIAL_HARVESTING',
        severity: 'CRITICAL',
        details: `Direct solicitation for sensitive authentication data: ${cred}.`,
      });
    }

    // Behavioral Pattern Evidence
    for (const pat of patterns) {
      // Map to clean human-facing signal title
      let signalTitle = pat.title;
      if (pat.patternType === 'OTP_REQUESTS') signalTitle = 'Requests an OTP';
      else if (pat.patternType === 'PASSWORD_REQUESTS') signalTitle = 'Requests an Account Password';
      else if (pat.patternType === 'PIN_REQUESTS') signalTitle = 'Requests a Banking PIN Code';
      else if (pat.patternType === 'URGENCY') signalTitle = 'Creates artificial urgency';
      else if (pat.patternType === 'EXCESSIVE_URGENCY') signalTitle = 'Imposes extreme short-fuse deadline';
      else if (pat.patternType === 'FAKE_BANK_COMMUNICATION') signalTitle = 'Claims to represent a financial institution';
      else if (pat.patternType === 'FAKE_GOVERNMENT_COMMUNICATION') signalTitle = 'Claims to represent a government authority';
      else if (pat.patternType === 'THREATS') signalTitle = 'Threatens police arrest or legal action';
      else if (pat.patternType === 'ACCOUNT_SUSPENSION') signalTitle = 'Claims account has been locked or suspended';
      else if (pat.patternType === 'FAKE_DELIVERIES') signalTitle = 'Claims package delivery failure with fees';
      else if (pat.patternType === 'FAKE_LOANS') signalTitle = 'Offers instant unsecured loan without collateral';
      else if (pat.patternType === 'FAKE_INVESTMENTS') signalTitle = 'Promises guaranteed investment returns';
      else if (pat.patternType === 'FAKE_REWARDS') signalTitle = 'Offers unsolicited lottery prize or reward';
      else if (pat.patternType === 'FAKE_JOBS') signalTitle = 'Offers unrealistic daily pay for online tasks';
      else if (pat.patternType === 'REMOTE_ACCESS_REQUESTS') signalTitle = 'Solicits remote desktop software installation';
      else if (pat.patternType === 'REQUESTS_TO_MOVE_PLATFORM') signalTitle = 'Attempts to move conversation off-platform to Telegram/WhatsApp';
      else if (pat.patternType === 'ADVANCE_FEE_REQUESTS') signalTitle = 'Demands upfront advance or clearance fee';

      evidence.push({
        signal: signalTitle,
        category: pat.patternType,
        severity: pat.severity === 'critical' ? 'CRITICAL' : pat.severity === 'high' ? 'HIGH' : 'MEDIUM',
        details: pat.description,
        matchedSnippet: pat.matchedPhrases[0] || undefined,
      });
    }

    // Suspicious Shortened or Obfuscated URL Evidence
    for (const u of entities.urls) {
      try {
        const parsed = new URL(u);
        const host = parsed.hostname.toLowerCase();
        if (EntityExtractor.SHORTENERS.has(host)) {
          evidence.push({
            signal: 'Contains a suspicious shortened URL',
            category: 'SUSPICIOUS_LINK',
            severity: 'HIGH',
            details: `Uses shortened domain '${host}' to conceal true landing page destination.`,
            matchedSnippet: u,
          });
        }
      } catch {
        // Invalid or defanged URL
        evidence.push({
          signal: 'Contains an obfuscated or defanged URL',
          category: 'SUSPICIOUS_LINK',
          severity: 'HIGH',
          details: 'Contains an evasively formatted or defanged web address.',
          matchedSnippet: u,
        });
      }
    }

    // Cryptocurrency / Untraceable Payment Evidence
    if (entities.cryptoAddresses.length > 0) {
      evidence.push({
        signal: 'Demands cryptocurrency transfer',
        category: 'UNTRACEABLE_PAYMENT',
        severity: 'HIGH',
        details: `Directs payments to untraceable crypto address: ${entities.cryptoAddresses[0].address} (${entities.cryptoAddresses[0].type}).`,
        matchedSnippet: entities.cryptoAddresses[0].address,
      });
    }

    // Obfuscation Evasion Evidence
    if (normalized.hasObfuscation) {
      evidence.push({
        signal: 'Evasive text obfuscation detected',
        category: 'EVASION_TECHNIQUE',
        severity: 'MEDIUM',
        details: `Detected evasion techniques: ${normalized.obfuscationTypes.join(', ')}.`,
      });
    }

    return evidence;
  }

  /**
   * Calculates weighted risk score based on independent signal dimensions
   */
  private calculateWeightedRiskScore(
    patterns: BehavioralPatternMatch[],
    entities: any,
    _normalized: any,
    _socialEng: SocialEngineeringAnalysis
  ): { riskScore: number; rawConfidence: number; scamCategories: string[] } {
    if (patterns.length === 0 && entities.urls.length === 0 && entities.cryptoAddresses.length === 0) {
      return { riskScore: 0, rawConfidence: 90, scamCategories: ['SAFE'] };
    }

    const categoryScores: Record<string, number> = {
      CREDENTIAL_HARVESTING: 0,
      ACCOUNT_TAKEOVER: 0,
      PHISHING: 0,
      FINANCIAL_FRAUD: 0,
      INVESTMENT_SCAM: 0,
      LOAN_SCAM: 0,
      DELIVERY_SCAM: 0,
      JOB_SCAM: 0,
      PRIZE_SCAM: 0,
      ROMANCE_SCAM: 0,
      IMPERSONATION: 0,
      REMOTE_ACCESS: 0,
      SOCIAL_ENGINEERING: 0,
    };

    let totalWeight = 0;
    let criticalCount = 0;
    const distinctPatternFamilies = new Set<string>();

    for (const pat of patterns) {
      distinctPatternFamilies.add(pat.patternType);
      totalWeight += pat.scoreContribution;
      if (pat.severity === 'critical') criticalCount++;

      switch (pat.patternType) {
        case 'OTP_REQUESTS':
        case 'PASSWORD_REQUESTS':
        case 'PIN_REQUESTS':
        case 'BANKING_CREDENTIAL_REQUESTS':
          categoryScores.CREDENTIAL_HARVESTING += pat.scoreContribution;
          categoryScores.ACCOUNT_TAKEOVER += pat.scoreContribution;
          categoryScores.PHISHING += Math.round(pat.scoreContribution * 0.8);
          break;
        case 'ACCOUNT_SUSPENSION':
          categoryScores.ACCOUNT_TAKEOVER += pat.scoreContribution;
          categoryScores.PHISHING += Math.round(pat.scoreContribution * 0.8);
          break;
        case 'THREATS':
        case 'FEAR_BASED_MANIPULATION':
        case 'AUTHORITY_IMPERSONATION':
          categoryScores.SOCIAL_ENGINEERING += pat.scoreContribution;
          categoryScores.IMPERSONATION += Math.round(pat.scoreContribution * 0.8);
          break;
        case 'URGENCY':
        case 'EXCESSIVE_URGENCY':
          categoryScores.SOCIAL_ENGINEERING += pat.scoreContribution;
          break;
        case 'FAKE_BANK_COMMUNICATION':
        case 'FAKE_GOVERNMENT_COMMUNICATION':
        case 'FAKE_CUSTOMER_SUPPORT':
        case 'IMPERSONATION':
          categoryScores.IMPERSONATION += pat.scoreContribution;
          categoryScores.PHISHING += Math.round(pat.scoreContribution * 0.7);
          break;
        case 'PAYMENT_REQUESTS':
        case 'ADVANCE_FEE_REQUESTS':
        case 'FINANCIAL_MANIPULATION':
          categoryScores.FINANCIAL_FRAUD += pat.scoreContribution;
          break;
        case 'FAKE_INVESTMENTS':
          categoryScores.INVESTMENT_SCAM += pat.scoreContribution;
          categoryScores.FINANCIAL_FRAUD += Math.round(pat.scoreContribution * 0.8);
          break;
        case 'FAKE_LOANS':
          categoryScores.LOAN_SCAM += pat.scoreContribution;
          categoryScores.FINANCIAL_FRAUD += Math.round(pat.scoreContribution * 0.9);
          break;
        case 'FAKE_DELIVERIES':
          categoryScores.DELIVERY_SCAM += pat.scoreContribution;
          categoryScores.PHISHING += Math.round(pat.scoreContribution * 0.8);
          break;
        case 'FAKE_JOBS':
          categoryScores.JOB_SCAM += pat.scoreContribution;
          break;
        case 'FAKE_REWARDS':
          categoryScores.PRIZE_SCAM += pat.scoreContribution;
          break;
        case 'ROMANCE_MANIPULATION':
          categoryScores.ROMANCE_SCAM += pat.scoreContribution;
          break;
        case 'REMOTE_ACCESS_REQUESTS':
          categoryScores.REMOTE_ACCESS += pat.scoreContribution;
          break;
        case 'SUSPICIOUS_LINKS':
          categoryScores.PHISHING += pat.scoreContribution;
          break;
      }
    }

    // Determine triggered scam categories (sorted by score)
    const sortedCategories = Object.entries(categoryScores)
      .filter(([_, score]) => score > 0)
      .sort((a, b) => b[1] - a[1])
      .map(([cat]) => cat);

    const maxCatScore = Math.max(...Object.values(categoryScores), 0);

    // Multi-Signal Correlation Multiplier
    let boost = 1.0;
    if (distinctPatternFamilies.size >= 4) {
      boost = 1.35;
    } else if (distinctPatternFamilies.size === 3) {
      boost = 1.25;
    } else if (distinctPatternFamilies.size === 2) {
      boost = 1.15;
    }

    let rawScore = Math.round((maxCatScore * 0.85 + totalWeight * 0.25) * boost);

    // Additional boost if entity corroborates threat (e.g. crypto address + investment scam, or shortened URL + phishing)
    if (entities.cryptoAddresses.length > 0 && categoryScores.INVESTMENT_SCAM > 0) rawScore += 15;
    if (entities.urls.some((u: string) => EntityExtractor.SHORTENERS.has(new URL(u).hostname)) && categoryScores.PHISHING > 0) rawScore += 10;
    if (entities.requestedCredentials.length > 0) rawScore += 15;
    if (categoryScores.LOAN_SCAM > 0 && (categoryScores.PHISHING > 0 || categoryScores.FINANCIAL_FRAUD > 0)) rawScore += 10;

    const riskScore = Math.min(100, rawScore);

    // Raw Confidence calculation
    let rawConfidence = 45;
    if (distinctPatternFamilies.size >= 3) rawConfidence += 30;
    else if (distinctPatternFamilies.size >= 2) rawConfidence += 20;
    else if (distinctPatternFamilies.size === 1) rawConfidence += 10;

    if (criticalCount > 0) rawConfidence += 15;
    if (entities.requestedCredentials.length > 0) rawConfidence += 10;
    if (entities.urls.length > 0 || entities.cryptoAddresses.length > 0) rawConfidence += 10;

    rawConfidence = Math.min(99, Math.max(25, rawConfidence));

    return {
      riskScore,
      rawConfidence,
      scamCategories: sortedCategories.length > 0 ? sortedCategories : ['SUSPICIOUS_MESSAGE'],
    };
  }

  /**
   * Applies the Anti-Unilateral Principle, ensures calibrated uncertainty,
   * and maps into the 6-tier classification taxonomy.
   */
  private classifyRiskAndConfidence(
    rawScore: number,
    rawConfidence: number,
    patterns: BehavioralPatternMatch[],
    entities: any,
    _intent: any
  ): { finalScore: number; finalRiskLevel: MessageRiskLevel; confidence: number } {
    const patternCount = patterns.length;

    // 1. Completely Clean Content
    if (patternCount === 0 && entities.urls.length === 0 && entities.cryptoAddresses.length === 0) {
      return {
        finalScore: 0,
        finalRiskLevel: 'SAFE',
        confidence: 90,
      };
    }

    // 2. Anti-Unilateral Rule: Single isolated indicator cannot declare MALICIOUS or HIGH_RISK
    const isSingleIsolatedUrgency =
      patternCount === 1 &&
      patterns[0].patternType === 'URGENCY' &&
      entities.urls.length === 0 &&
      entities.cryptoAddresses.length === 0 &&
      entities.requestedCredentials.length === 0;

    const isSingleIsolatedLinkClick =
      patternCount === 1 &&
      patterns[0].patternType === 'SUSPICIOUS_LINKS' &&
      entities.urls.length === 0 &&
      entities.requestedCredentials.length === 0;

    const isSingleOffPlatform =
      patternCount === 1 &&
      patterns[0].patternType === 'REQUESTS_TO_MOVE_PLATFORM' &&
      entities.requestedCredentials.length === 0;

    // Uncertainty condition: Isolated ambiguous indicator without corroborating threat families
    if (isSingleIsolatedUrgency || isSingleIsolatedLinkClick || isSingleOffPlatform) {
      return {
        finalScore: Math.min(25, rawScore),
        finalRiskLevel: 'UNKNOWN_INSUFFICIENT_EVIDENCE',
        confidence: 45, // Calibrated confidence < 50%
      };
    }

    // Single non-critical pattern cap at SUSPICIOUS (max 45)
    let score = rawScore;
    if (patternCount === 1 && patterns[0].severity !== 'critical') {
      score = Math.min(45, score);
    }

    // Map into 6-tier taxonomy
    let riskLevel: MessageRiskLevel = 'LOW_RISK';
    let confidence = rawConfidence;

    if (score >= 80 && confidence >= 70) {
      riskLevel = 'CONFIRMED_MALICIOUS';
    } else if (score >= 60 && confidence >= 60) {
      riskLevel = 'HIGHLY_SUSPICIOUS';
    } else if (score >= 40) {
      riskLevel = 'SUSPICIOUS';
    } else if (score >= 20) {
      riskLevel = 'LOW_RISK';
    } else {
      riskLevel = 'SAFE';
    }

    return {
      finalScore: score,
      finalRiskLevel: riskLevel,
      confidence,
    };
  }

  /**
   * Generates grounded, explainable reasoning and specific protective recommendations
   */
  private generateGroundedExplanation(
    riskLevel: MessageRiskLevel,
    _riskScore: number,
    scamCategories: string[],
    evidence: MessageEvidenceItem[],
    entities: any,
    _intent: any,
    language: string
  ): { explanation: string; recommendedAction: string } {
    const isKm = language === 'km' || language === 'km-en';

    if (riskLevel === 'SAFE') {
      return {
        explanation: isKm
          ? 'សារនេះមិនមានសញ្ញា ឬពាក្យសម្ដីបោកប្រាស់ គំរាមកំហែង ឬលួចទិន្នន័យឡើយ។'
          : 'No deceptive phrasing, urgency pressure, credential harvesting, or payment manipulation was detected in this message.',
        recommendedAction: isKm
          ? 'សារនេះមានសុវត្ថិភាពជាទូទៅ។ សូមរក្សាការប្រុងប្រយ័ត្នតាមស្តង់ដារឌីជីថល។'
          : 'Message appears safe and conversational. Exercise standard digital caution.',
      };
    }

    if (riskLevel === 'UNKNOWN_INSUFFICIENT_EVIDENCE') {
      return {
        explanation: isKm
          ? 'ខ្ញុំមិនមានភស្តុតាងគ្រប់គ្រាន់ដើម្បីកំណត់ថាតើសារនេះជាការបោកប្រាស់ឬយ៉ាងណានោះទេ។ សារនេះមានពាក្យគន្លឹះស្រពិចស្រពិល ប៉ុន្តែខ្វះសញ្ញាគំរាមកំហែងច្បាស់លាស់។'
          : "I don't have enough evidence to determine whether this is a scam. The content contains ambiguous terms (e.g., isolated urgency or off-platform request), but lacks definitive malicious indicators.",
        recommendedAction: isKm
          ? 'លទ្ធផលមិនទាន់ប្រាកដប្រជា៖ សូមកុំផ្ទេរប្រាក់ ឬចុចលើតំណភ្ជាប់រហូតដល់អ្នកបានផ្ទៀងផ្ទាត់ដោយផ្ទាល់ជាមួយអ្នកផ្ញើ។'
          : 'UNCERTAIN EVIDENCE — EXERCISE CAUTION: Do not transfer funds, share personal information, or click links until verified independently through verified official channels.',
      };
    }

    // High risk or confirmed malicious explanation
    const topSignals = evidence.slice(0, 3).map((e) => e.signal).join(', ');
    const primaryCat = scamCategories[0] || 'SCAM';

    let explanation = `High-risk scam indicators detected (${topSignals}). The message exhibits clear hallmarks of ${primaryCat.replace(/_/g, ' ').toLowerCase()} designed to manipulate the recipient.`;
    if (entities.requestedCredentials.length > 0) {
      explanation += ` Specifically attempts to illicitly harvest: ${entities.requestedCredentials.join(', ')}.`;
    }

    let recommendedAction = 'Do not respond, click links, or send funds. Block the sender immediately.';
    if (entities.requestedCredentials.length > 0) {
      recommendedAction = 'CRITICAL WARNING: Never share OTP verification codes, passwords, or PINs. Legitimate banks and support teams never ask for credentials via message.';
    } else if (scamCategories.includes('FINANCIAL_FRAUD') || scamCategories.includes('INVESTMENT_SCAM')) {
      recommendedAction = 'FINANCIAL FRAUD ALERT: Do not send money, wire transfers, or cryptocurrency. Legitimate investments never guarantee 100% risk-free returns.';
    } else if (scamCategories.includes('DELIVERY_SCAM')) {
      recommendedAction = 'PACKAGE SCAM WARNING: Do not click the tracking link or pay customs clearance fees. Check your shipment status directly on the official courier website.';
    } else if (scamCategories.includes('LOAN_SCAM')) {
      recommendedAction = 'PREDATORY LOAN ALERT: Do not pay any upfront deposit or clearance fee. Unregulated online loans are designed to extract advance fees.';
    } else if (scamCategories.includes('REMOTE_ACCESS')) {
      recommendedAction = 'EXTREME HAZARD: Never install AnyDesk or TeamViewer on instruction from an incoming message. This grants attackers full control of your device.';
    }

    return { explanation, recommendedAction };
  }

  private buildEmptyResult(startTime: number): MessageScamResult {
    return {
      riskLevel: 'SAFE',
      riskScore: 0,
      confidence: 100,
      scamCategories: ['SAFE'],
      indicators: [],
      extractedEntities: {
        urls: [],
        phoneNumbers: [],
        emailAddresses: [],
        cryptoAddresses: [],
        bankAccounts: [],
        paymentHandles: [],
        socialHandles: [],
        brands: [],
        requestedCredentials: [],
      },
      behavioralPatterns: [],
      intent: {
        primaryIntent: 'BENIGN_CONVERSATION',
        confidence: 100,
        isSolicitation: false,
        summary: 'Empty input provided.',
      },
      socialEngineering: {
        urgencyLevel: 'NONE',
        fearTactics: false,
        authorityClaim: false,
        manipulationScore: 0,
      },
      recommendedAction: 'No text provided for analysis.',
      explanation: 'Empty content analyzed.',
      evidence: [],
      language: 'unknown',
      normalizedText: '',
      executionTimeMs: Date.now() - startTime,
    };
  }
}

export const messageScamEngine = new MessageScamEngine();
