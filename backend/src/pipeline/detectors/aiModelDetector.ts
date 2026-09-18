import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult, DetectorSeverity } from '../types';
import { aiProxyService } from '../../modules/ai/aiProxyService';

export class AiModelDetector implements IDetector {
  readonly name = 'ai_model_detector';
  readonly type = 'ai' as const;
  readonly enabled = true;

  supports(type: InputType): boolean {
    return type === 'TEXT' || type === 'URL' || type === 'QR';
  }

  async detect(input: NormalizedInput, _context: PipelineContext): Promise<DetectorResult | null> {
    const textToAnalyze = input.normalizedText || input.raw;
    if (!textToAnalyze || !textToAnalyze.trim()) {
      return null;
    }

    // Optimization 14: Limit AI calls when deterministic analysis provides sufficient evidence
    // If URL is on trusted authority whitelist, return safe result without redundant remote AI call
    if (input.type === 'URL' && input.urlDomain) {
      const parts = input.urlDomain.toLowerCase().split('.');
      const baseDomain = parts.slice(-2).join('.');
      const trustedDomains = ['google.com', 'youtube.com', 'wikipedia.org', 'microsoft.com', 'apple.com', 'github.com'];
      if (trustedDomains.includes(baseDomain) || trustedDomains.includes(input.urlDomain.toLowerCase())) {
        return {
          detector_name: this.name,
          detector_type: this.type,
          score: 0,
          severity: 'safe',
          confidence: 95,
          evidence: {
            summary: `Verified authority domain (${input.urlDomain}) — deterministic trust applied.`,
            indicators: [],
            details: {
              threat_category: 'SAFE',
              signals_count: 0,
              bypassed_ai_call: true,
            },
          },
          execution_time_ms: 0,
        };
      }
    }

    const startTime = Date.now();
    try {
      const aiRes = (input.type === 'URL' && input.normalizedUrl)
        ? await aiProxyService.analyzeUrl(input.normalizedUrl)
        : await aiProxyService.analyzeMessage(textToAnalyze);
      const duration = Date.now() - startTime;

      const score = aiRes.risk_score || 0;
      let severity: DetectorSeverity = 'safe';
      if (score >= 75) severity = 'critical';
      else if (score >= 50) severity = 'high';
      else if (score >= 30) severity = 'medium';
      else if (score > 0) severity = 'low';

      const indicators = (aiRes.signals || []).map((s: any) => `${s.title}: ${s.description}`);

      return {
        detector_name: this.name,
        detector_type: this.type,
        score,
        severity,
        confidence: aiRes.confidence_score || 80,
        evidence: {
          summary: aiRes.summary || 'AI Model heuristic evaluation complete.',
          indicators,
          details: {
            threat_category: aiRes.threat_category,
            signals_count: (aiRes.signals || []).length,
            ai_id: aiRes.id,
          },
        },
        execution_time_ms: duration,
      };
    } catch {
      // AI Engine offline or timed out; pipeline will gracefully proceed with heuristic, pattern, reputation & community detectors!
      return null;
    }
  }
}

export const aiModelDetector = new AiModelDetector();
