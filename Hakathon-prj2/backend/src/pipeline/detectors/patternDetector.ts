import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult, DetectorSeverity } from '../types';
import { scamIntelligenceService } from '../../modules/intelligence';

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

    const comparison = await scamIntelligenceService.matchContent(textToEvaluate);

    let severity: DetectorSeverity = 'safe';
    if (comparison.highest_severity === 'critical') severity = 'critical';
    else if (comparison.highest_severity === 'high') severity = 'high';
    else if (comparison.highest_severity === 'medium') severity = 'medium';
    else if (comparison.highest_severity === 'low') severity = 'low';

    const confidence = comparison.matched_patterns.length > 0
      ? Math.min(95, 70 + comparison.matched_patterns.length * 10)
      : 60;

    const summary = comparison.matched
      ? `Identified ${comparison.matched_patterns.length} scam intelligence patterns (${comparison.categories_detected.join(', ')}).`
      : `No signature scam campaign patterns matched.`;

    const indicators = comparison.matched_patterns.map(
      (p) => `${p.description} (${p.category}) [severity: ${p.severity}]`
    );

    const legacyCategoryMap: Record<string, string> = {
      cryptocurrency_scam: 'CRYPTO_SCAM',
      lottery_scam: 'PRIZE_SCAM',
      fake_job: 'JOB_SCAM',
      fake_investment: 'INVESTMENT_SCAM',
      impersonation: 'IMPERSONATION',
      romance_scam: 'ROMANCE_SCAM',
      phishing: 'PHISHING',
      payment_scam: 'PAYMENT_SCAM',
      account_takeover: 'ACCOUNT_TAKEOVER',
      tech_support_scam: 'TECH_SUPPORT_SCAM',
    };

    const categoriesWithAliases = new Set<string>();
    for (const cat of comparison.categories_detected) {
      categoriesWithAliases.add(cat);
      categoriesWithAliases.add(cat.toUpperCase());
      const mapped = legacyCategoryMap[cat.toLowerCase()];
      if (mapped) categoriesWithAliases.add(mapped);
    }

    return {
      detector_name: this.name,
      detector_type: this.type,
      score: comparison.scam_score,
      severity,
      confidence,
      evidence: {
        summary,
        indicators,
        details: {
          matched_count: comparison.matched_patterns.length,
          categories: Array.from(categoriesWithAliases),
          rule_ids: comparison.matched_patterns.map((p) => p.id),
          highest_severity: comparison.highest_severity,
          recommended_action: comparison.recommended_action,
        },
      },
      execution_time_ms: comparison.execution_time_ms,
    };
  }
}

export const scamPatternDetector = new ScamPatternDetector();
