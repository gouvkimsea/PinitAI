import { analyzeUrl, normalizeUrl, UrlAnalysisResult } from '../../scanners/url/urlScanner';
import { threatIntel } from '../../scanners/threatIntel/threatIntelProvider';
import { DetectionItem } from '../../types';
import { logger } from '../../utils/logger';

export interface ComprehensiveUrlResult {
  metadata: UrlAnalysisResult['metadata'];
  detections: DetectionItem[];
  threatIntelProvider?: string;
  enginesEvaluated: string[];
}

export class UrlAnalyzer {
  /**
   * Performs end-to-end security analysis of a URL, including SSRF, heuristics,
   * keyword extraction, brand impersonation, and threat intelligence lookups.
   */
  async analyze(rawUrl: string): Promise<ComprehensiveUrlResult> {
    logger.info('Performing modular URL analysis', { url: rawUrl });
    const normalized = normalizeUrl(rawUrl);

    // 1. Run core URL analysis (SSRF, keywords, domain heuristics)
    const urlAnalysis = await analyzeUrl(normalized);

    // 2. Query threat intelligence for the domain
    const domainIntel = await threatIntel.checkDomain(urlAnalysis.metadata.domain);

    const allDetections: DetectionItem[] = [...urlAnalysis.detections];
    if (domainIntel && domainIntel.detections) {
      allDetections.push(...domainIntel.detections);
    }

    const enginesEvaluated = ['SSRFGuard', 'URLValidator', 'URLPhishingEngine'];
    if (domainIntel) {
      enginesEvaluated.push(domainIntel.provider);
    }

    return {
      metadata: urlAnalysis.metadata,
      detections: allDetections,
      threatIntelProvider: domainIntel ? domainIntel.provider : undefined,
      enginesEvaluated,
    };
  }

  /**
   * Executes deep multi-dimensional URL intelligence analysis.
   */
  async analyzeIntelligence(rawUrl: string) {
    const { urlIntelligence } = await import('./urlIntelligence');
    return urlIntelligence.analyze(rawUrl);
  }

  normalize(url: string): string {
    return normalizeUrl(url);
  }
}

export const urlAnalyzer = new UrlAnalyzer();
