import { IDetector, NormalizedInput, PipelineContext, DetectorResult, EvidenceCollection, DetectorSeverity } from '../types';
import { logger } from '../../utils/logger';

export class EvidenceCollector {
  private readonly defaultTimeoutMs: number;

  constructor(timeoutMs: number = 3000) {
    this.defaultTimeoutMs = timeoutMs;
  }

  /**
   * Concurrently collects evidence across all applicable detectors with isolated error handling and timeouts.
   */
  async collect(
    detectors: IDetector[],
    input: NormalizedInput,
    context: PipelineContext
  ): Promise<EvidenceCollection> {
    const promises = detectors.map(async (detector): Promise<DetectorResult | null> => {
      try {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const timeoutPromise = new Promise<null>((resolve) => {
          timer = setTimeout(() => {
            logger.trackDetectionFailure({
              scanId: context.scanId,
              detectorName: detector.name,
              error: `Timed out after ${this.defaultTimeoutMs}ms`,
              context: { inputType: input.type },
            });
            resolve(null);
          }, this.defaultTimeoutMs);
        });

        const executionPromise = detector.detect(input, context);
        try {
          return await Promise.race([executionPromise, timeoutPromise]);
        } finally {
          if (timer) clearTimeout(timer);
        }
      } catch (err) {
        logger.trackDetectionFailure({
          scanId: context.scanId,
          detectorName: detector.name,
          error: (err as Error).message,
          context: { inputType: input.type },
        });
        return null;
      }
    });

    const settled = await Promise.all(promises);
    const validResults: DetectorResult[] = settled.filter(
      (res): res is DetectorResult => res !== null
    );

    let maliciousCount = 0;
    let suspiciousCount = 0;
    let cleanCount = 0;
    const allIndicators: string[] = [];
    const categories: string[] = [];

    const severityOrder: Record<DetectorSeverity, number> = {
      safe: 0,
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    let maxSevNum = 0;
    let highestSeverity: DetectorSeverity = 'safe';

    for (const res of validResults) {
      if (res.score >= 70) {
        maliciousCount++;
      } else if (res.score >= 40) {
        suspiciousCount++;
      } else {
        cleanCount++;
      }

      if (res.evidence.indicators) {
        allIndicators.push(...res.evidence.indicators);
      }

      if (res.evidence.details?.primary_category) {
        categories.push(res.evidence.details.primary_category);
      }
      if (res.evidence.details?.categories) {
        categories.push(...res.evidence.details.categories);
      }

      const sevNum = severityOrder[res.severity] || 0;
      if (sevNum > maxSevNum) {
        maxSevNum = sevNum;
        highestSeverity = res.severity;
      }
    }

    return {
      detectorResults: validResults,
      totalDetectorsRan: validResults.length,
      maliciousCount,
      suspiciousCount,
      cleanCount,
      indicators: Array.from(new Set(allIndicators)),
      detectedThreatCategories: Array.from(new Set(categories.filter((c) => c && c !== 'SAFE'))),
      highestSeverity,
    };
  }
}

export const evidenceCollector = new EvidenceCollector();
