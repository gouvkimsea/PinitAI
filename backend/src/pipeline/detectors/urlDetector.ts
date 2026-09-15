import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult, DetectorSeverity } from '../types';
import { urlIntelligence } from '../../modules/url/urlIntelligence';

export class UrlAnalysisDetector implements IDetector {
  readonly name = 'url_security_detector';
  readonly type = 'url' as const;
  readonly enabled = true;

  supports(type: InputType): boolean {
    return type === 'URL' || type === 'QR' || type === 'TEXT';
  }

  async detect(input: NormalizedInput, _context: PipelineContext): Promise<DetectorResult | null> {
    const targetUrl = input.normalizedUrl || (input.extractedUrls.length > 0 ? input.extractedUrls[0] : null);
    if (!targetUrl) {
      return null;
    }

    const startTime = Date.now();
    const intel = await urlIntelligence.analyze(targetUrl);
    const duration = Date.now() - startTime;

    let severity: DetectorSeverity = 'safe';
    if (intel.severity === 'critical') {
      severity = 'critical';
    } else if (intel.severity === 'high') {
      severity = 'high';
    } else if (intel.severity === 'medium' || intel.severity === 'needs_review') {
      severity = 'medium';
    } else if (intel.severity === 'low') {
      severity = 'low';
    }

    return {
      detector_name: this.name,
      detector_type: this.type,
      score: intel.compositeScore,
      severity,
      confidence: intel.confidence,
      evidence: {
        summary: intel.evidence.summary,
        indicators: intel.indicators,
        details: {
          domain: intel.metadata.domain,
          is_https: intel.metadata.isHttps,
          has_redirects: intel.networkProbe.hasRedirects,
          redirect_count: intel.networkProbe.redirectCount,
          redirect_chain: intel.networkProbe.redirectChain,
          ip_address: intel.metadata.ipAddress,
          detections_count: intel.detections.length,
          brand_impersonation: intel.brandImpersonation,
          structural: intel.structural,
          network_probe: intel.networkProbe,
          recommended_action: intel.recommendedAction,
        },
      },
      execution_time_ms: duration,
    };
  }
}

export const urlAnalysisDetector = new UrlAnalysisDetector();
