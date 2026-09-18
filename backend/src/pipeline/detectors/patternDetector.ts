import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult, DetectorSeverity } from '../types';
import { scamIntelligenceService, scamIntelligenceEngine } from '../../modules/intelligence';

export class ScamPatternDetector implements IDetector {
  readonly name = 'scam_pattern_detector';
  readonly type = 'pattern' as const;
  readonly enabled = true;

  supports(type: InputType): boolean {
    return type === 'TEXT' || type === 'URL' || type === 'QR';
  }

  async detect(input: NormalizedInput, _context: PipelineContext): Promise<DetectorResult | null> {
    const textToEvaluate = `${input.normalizedText || ''} ${input.normalizedUrl || ''} ${input.raw || ''}`;
    if (!textToEvaluate.trim()) {
      return null;
    }

    // Evaluate against both the database intelligence service and modular rule engine concurrently
    const [comparison, modularVerdict] = await Promise.all([
      scamIntelligenceService.matchContent(textToEvaluate),
      scamIntelligenceEngine.evaluate({
        text: input.raw || '',
        normalizedText: input.normalizedText,
        url: input.normalizedUrl,
        qr: input.type === 'QR' ? input.raw : undefined,
      }),
    ]);

    let severity: DetectorSeverity = 'safe';
    if (comparison.highest_severity === 'critical' || modularVerdict.threatLevel === 'MALICIOUS') {
      severity = 'critical';
    } else if (comparison.highest_severity === 'high') {
      severity = 'high';
    } else if (comparison.highest_severity === 'medium' || modularVerdict.threatLevel === 'SUSPICIOUS') {
      severity = 'medium';
    } else if (comparison.highest_severity === 'low' || modularVerdict.threatLevel === 'LOW') {
      severity = 'low';
    }

    const totalMatches = comparison.matched_patterns.length + modularVerdict.triggeredRules.length;

    // Harmonize confidence: multi-signal correlation boosts confidence
    const confidence = totalMatches > 0
      ? Math.min(98, Math.max(modularVerdict.confidence, 70 + comparison.matched_patterns.length * 10))
      : 60;

    // Harmonize score
    const combinedScore = Math.min(
      100,
      Math.max(comparison.scam_score, modularVerdict.scamScore)
    );

    const legacyCategoryMap: Record<string, string> = {
      cryptocurrency_scam: 'CRYPTO_SCAM',
      crypto_scams: 'CRYPTO_SCAM',
      lottery_scam: 'PRIZE_SCAM',
      giveaway_scams: 'PRIZE_SCAM',
      fake_job: 'JOB_SCAM',
      fake_employment: 'JOB_SCAM',
      fake_investment: 'INVESTMENT_SCAM',
      impersonation: 'IMPERSONATION',
      romance_scam: 'ROMANCE_SCAM',
      romance_scams: 'ROMANCE_SCAM',
      phishing: 'PHISHING',
      payment_scam: 'PAYMENT_SCAM',
      payment_fraud: 'PAYMENT_SCAM',
      financial_fraud: 'FINANCIAL_FRAUD',
      credential_theft: 'CREDENTIAL_THEFT',
      otp_theft: 'OTP_THEFT',
      social_engineering: 'SOCIAL_ENGINEERING',
      fake_shopping: 'SHOPPING_SCAM',
      fake_delivery: 'DELIVERY_SCAM',
      fake_support: 'TECH_SUPPORT_SCAM',
      tech_support_scam: 'TECH_SUPPORT_SCAM',
      loan_scams: 'LOAN_SCAM',
      account_takeover: 'ACCOUNT_TAKEOVER',
      malware_delivery: 'MALWARE_DELIVERY',
      malicious_downloads: 'MALICIOUS_DOWNLOADS',
      qr_scams: 'QR_SCAM',
    };

    const categoriesWithAliases = new Set<string>();
    for (const cat of comparison.categories_detected) {
      categoriesWithAliases.add(cat);
      categoriesWithAliases.add(cat.toUpperCase());
      const mapped = legacyCategoryMap[cat.toLowerCase()];
      if (mapped) categoriesWithAliases.add(mapped);
    }

    for (const cat of modularVerdict.categoriesDetected) {
      categoriesWithAliases.add(cat);
      categoriesWithAliases.add(cat.toUpperCase());
      const mapped = legacyCategoryMap[cat.toLowerCase()];
      if (mapped) categoriesWithAliases.add(mapped);
    }

    const indicators: string[] = [
      ...comparison.matched_patterns.map((p) => `${p.description} (${p.category}) [severity: ${p.severity}]`),
      ...modularVerdict.triggeredRules.map(
        (r) => `[${r.ruleId}] ${r.description} (${r.category}) [severity: ${r.severity}]`
      ),
    ];

    const ruleIds = [
      ...comparison.matched_patterns.map((p) => p.id),
      ...modularVerdict.triggeredRules.map((r) => r.ruleId),
    ];

    const summary = totalMatches > 0
      ? `Identified ${totalMatches} scam intelligence patterns & modular rules across ${categoriesWithAliases.size} indicators.`
      : `No signature scam campaign patterns matched.`;

    return {
      detector_name: this.name,
      detector_type: this.type,
      score: combinedScore,
      severity,
      confidence,
      evidence: {
        summary,
        indicators,
        details: {
          matched_count: totalMatches,
          categories: Array.from(categoriesWithAliases),
          rule_ids: ruleIds,
          highest_severity: comparison.highest_severity !== 'safe' ? comparison.highest_severity : severity,
          recommended_action: comparison.recommended_action || (modularVerdict.isScam ? 'BLOCK_AND_FLAG' : 'ALLOW'),
          modular_signals: {
            is_scam: modularVerdict.isScam,
            threat_level: modularVerdict.threatLevel,
            category_count: modularVerdict.categoryCount,
            is_single_weak_rule: modularVerdict.isSingleWeakRule,
            explanation: modularVerdict.explanation,
          },
        },
      },
      execution_time_ms: comparison.execution_time_ms + modularVerdict.evaluationTimeMs,
    };
  }
}

export const scamPatternDetector = new ScamPatternDetector();
