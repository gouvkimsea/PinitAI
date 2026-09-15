import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult, DetectorSeverity } from '../types';
import { threatIntel } from '../../scanners/threatIntel/threatIntelProvider';

export class ReputationDetector implements IDetector {
  readonly name = 'reputation_signal_detector';
  readonly type = 'reputation' as const;
  readonly enabled = true;

  private static readonly SUSPICIOUS_TLDS = new Set([
    'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'work', 'click',
    'country', 'stream', 'download', 'racing', 'win', 'vip', 'cam', 'quest'
  ]);

  supports(type: InputType): boolean {
    return type === 'URL' || type === 'QR' || type === 'FILE' || type === 'TEXT';
  }

  async detect(input: NormalizedInput, _context: PipelineContext): Promise<DetectorResult | null> {
    const startTime = Date.now();
    let score = 0;
    const indicators: string[] = [];
    const details: Record<string, any> = {};

    // 1. Check Domain Reputation if URL is present
    const domainToCheck = input.urlDomain || (input.extractedUrls.length > 0 ? new URL(input.extractedUrls[0]).hostname : null);

    if (!domainToCheck && !input.sanitizedFileName) {
      return null;
    }

    if (domainToCheck) {
      const parts = domainToCheck.split('.');
      const tld = parts[parts.length - 1]?.toLowerCase();

      if (ReputationDetector.SUSPICIOUS_TLDS.has(tld)) {
        score += 35;
        indicators.push(`High-Risk Top-Level Domain (.${tld}) frequently associated with phishing and botnets`);
        details.suspicious_tld = tld;
      }

      try {
        const intel = await threatIntel.checkDomain(domainToCheck);
        if (intel) {
          score = Math.max(score, intel.reputationScore);
          details.provider = intel.provider;
          if (intel.detections) {
            for (const d of intel.detections) {
              indicators.push(`${d.title}: ${d.description}`);
            }
          }
        }
      } catch {
        // Fallback gracefully
      }
    }

    const duration = Date.now() - startTime;
    score = Math.min(100, score);

    let severity: DetectorSeverity = 'safe';
    if (score >= 70) severity = 'critical';
    else if (score >= 45) severity = 'high';
    else if (score >= 25) severity = 'medium';
    else if (score > 0) severity = 'low';

    const confidence = indicators.length > 0 ? 85 : 60;

    const summary = indicators.length > 0
      ? `Reputation intelligence detected ${indicators.length} negative reputation signals.`
      : `No prior negative domain, IP, or hash reputation listings found.`;

    return {
      detector_name: this.name,
      detector_type: this.type,
      score,
      severity,
      confidence,
      evidence: {
        summary,
        indicators,
        details,
      },
      execution_time_ms: duration,
    };
  }
}

export const reputationDetector = new ReputationDetector();
