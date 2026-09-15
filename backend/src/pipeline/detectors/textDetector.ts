import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult, DetectorSeverity } from '../types';
import { textDetector as coreTextDetector } from '../../modules/text/textDetector';

export class TextAnalysisDetector implements IDetector {
  readonly name = 'text_linguistic_detector';
  readonly type = 'text' as const;
  readonly enabled = true;

  supports(type: InputType): boolean {
    return type === 'TEXT' || type === 'QR';
  }

  async detect(input: NormalizedInput, _context: PipelineContext): Promise<DetectorResult | null> {
    const textToScan = input.normalizedText || input.raw;
    if (!textToScan || !textToScan.trim()) {
      return null;
    }

    const startTime = Date.now();
    let result = coreTextDetector.detectTextThreats(textToScan);
    if (input.deobfuscatedText && input.deobfuscatedText !== textToScan) {
      const deobfResult = coreTextDetector.detectTextThreats(input.deobfuscatedText);
      if (deobfResult.structured.score > result.structured.score) {
        result = deobfResult;
      }
    }
    const structured = result.structured;
    const duration = Date.now() - startTime;

    let severity: DetectorSeverity = 'safe';
    if (structured.severity === 'needs_review') {
      severity = 'medium';
    } else if (structured.severity === 'critical') {
      severity = 'critical';
    } else if (structured.severity === 'high') {
      severity = 'high';
    } else if (structured.severity === 'medium') {
      severity = 'medium';
    } else if (structured.severity === 'low') {
      severity = 'low';
    }

    return {
      detector_name: this.name,
      detector_type: this.type,
      score: structured.score,
      severity,
      confidence: structured.confidence,
      evidence: {
        summary: structured.evidence.summary,
        indicators: structured.evidence.indicators,
        details: {
          detected_patterns: structured.detected_patterns,
          suspicious_phrases: structured.suspicious_phrases,
          scam_category: structured.scam_category,
          severity: structured.severity,
          confidence: structured.confidence,
          recommended_action: structured.recommended_action,
          reasoning: structured.evidence.reasoning,
          language: structured.language,
          category_scores: structured.evidence.category_scores,
          signals_count: result.signals.length,
        },
      },
      execution_time_ms: duration,
    };
  }
}

export const textAnalysisDetector = new TextAnalysisDetector();
