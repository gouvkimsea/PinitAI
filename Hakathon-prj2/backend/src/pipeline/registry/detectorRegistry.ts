import { IDetector, InputType } from '../types';
import { textAnalysisDetector } from '../detectors/textDetector';
import { urlAnalysisDetector } from '../detectors/urlDetector';
import { fileAnalysisDetector } from '../detectors/fileDetector';
import { scamPatternDetector } from '../detectors/patternDetector';
import { reputationDetector } from '../detectors/reputationDetector';
import { communityReportDetector } from '../detectors/communityReportDetector';
import { aiModelDetector } from '../detectors/aiModelDetector';
import { ImpersonationDetector } from '../detectors/impersonationDetector';
import { logger } from '../../utils/logger';

export class DetectorRegistry {
  private detectors: Map<string, IDetector> = new Map();

  constructor() {
    this.registerDefaultDetectors();
  }

  private registerDefaultDetectors(): void {
    this.register(textAnalysisDetector);
    this.register(urlAnalysisDetector);
    this.register(fileAnalysisDetector);
    this.register(scamPatternDetector);
    this.register(new ImpersonationDetector());
    this.register(reputationDetector);
    this.register(communityReportDetector);
    this.register(aiModelDetector);
  }

  /**
   * Registers a new or custom detector into the pipeline
   */
  register(detector: IDetector): void {
    this.detectors.set(detector.name, detector);
    logger.debug('Registered detector in pipeline registry', { name: detector.name, type: detector.type });
  }

  /**
   * Removes a detector from the pipeline by name
   */
  unregister(name: string): boolean {
    return this.detectors.delete(name);
  }

  /**
   * Retrieves all enabled detectors supporting the given input type
   */
  getDetectorsFor(type: InputType): IDetector[] {
    return Array.from(this.detectors.values()).filter(
      (d) => d.enabled && d.supports(type)
    );
  }

  /**
   * Lists all registered detectors and their active status
   */
  listDetectors(): Array<{ name: string; type: string; enabled: boolean }> {
    return Array.from(this.detectors.values()).map((d) => ({
      name: d.name,
      type: d.type,
      enabled: d.enabled,
    }));
  }
}

export const detectorRegistry = new DetectorRegistry();
