import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult, DetectorSeverity } from '../types';
import { secureFileAnalyzer } from '../../modules/file/secureFileAnalyzer';

export class FileAnalysisDetector implements IDetector {
  readonly name = 'file_security_detector';
  readonly type = 'file' as const;
  readonly enabled = true;

  supports(type: InputType): boolean {
    return type === 'FILE';
  }

  async detect(input: NormalizedInput, _context: PipelineContext): Promise<DetectorResult | null> {
    if (input.type !== 'FILE' || !input.raw) {
      return null;
    }

    const filePath = input.raw; // filePath passed in raw
    const fileName = input.sanitizedFileName || 'upload.bin';
    const mimeType = input.fileMimeType || 'application/octet-stream';

    const startTime = Date.now();

    try {
      // Sandboxed static analysis without executing the file
      const result = await secureFileAnalyzer.analyze(filePath, fileName, mimeType, {
        autoCleanup: false, // Managed by calling orchestrator or queue
      });

      let severity: DetectorSeverity = 'safe';
      if (result.classification === 'Critical Risk') severity = 'critical';
      else if (result.classification === 'High Risk') severity = 'high';
      else if (result.classification === 'Suspicious') severity = 'medium';
      else if (result.classification === 'Mild Risk') severity = 'low';

      return {
        detector_name: this.name,
        detector_type: this.type,
        score: result.risk_score,
        severity,
        confidence: result.evidence.file_hashes.sha256 ? 90 : 70,
        evidence: {
          summary: result.evidence.summary,
          indicators: result.detected_indicators,
          details: {
            file_type: result.file_type,
            file_size: result.file_size,
            detected_indicators: result.detected_indicators,
            risk_score: result.risk_score,
            classification: result.classification,
            evidence: result.evidence,
            recommended_action: result.recommended_action,
            file_name: fileName,
            sha256: result.evidence.file_hashes.sha256,
          },
        },
        execution_time_ms: Date.now() - startTime,
      };
    } catch (err) {
      // In case physical file is not on disk (e.g. metadata-only scan)
      return {
        detector_name: this.name,
        detector_type: this.type,
        score: 0,
        severity: 'safe',
        confidence: 60,
        evidence: {
          summary: `File static inspection incomplete: ${(err as Error).message}`,
          indicators: [`Notice: ${(err as Error).message}`],
          details: {
            file_name: fileName,
          },
        },
        execution_time_ms: Date.now() - startTime,
      };
    }
  }
}

export const fileAnalysisDetector = new FileAnalysisDetector();
