import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult, DetectorSeverity } from '../types';
import prisma from '../../database/client';
import { LruCache } from '../../utils/lruCache';
import { metricsCollector } from '../../modules/monitoring/metricsCollector';

export class CommunityReportDetector implements IDetector {
  readonly name = 'community_intelligence_detector';
  readonly type = 'community' as const;
  readonly enabled = true;
  private reportCache = new LruCache<string, Array<{ id: string; scamType: string; description: string }>>({
    maxSize: 1000,
    defaultTtlMs: 5 * 60 * 1000, // 5 minutes TTL
  });

  supports(_type: InputType): boolean {
    return true; // Checks community reports across all modalities
  }

  async detect(input: NormalizedInput, _context: PipelineContext): Promise<DetectorResult | null> {
    const startTime = Date.now();
    const targetsToCheck: string[] = [];

    if (input.urlDomain) targetsToCheck.push(input.urlDomain);
    if (input.normalizedUrl) targetsToCheck.push(input.normalizedUrl);
    if (input.extractedUrls.length > 0) targetsToCheck.push(...input.extractedUrls);
    if (input.extractedPhoneNumbers.length > 0) targetsToCheck.push(...input.extractedPhoneNumbers);
    if (input.sanitizedFileName) targetsToCheck.push(input.sanitizedFileName);

    let matchingReports: Array<{ id: string; scamType: string; description: string }> = [];

    if (targetsToCheck.length > 0) {
      const cacheKey = targetsToCheck.sort().join('|');
      const cached = this.reportCache.get(cacheKey);
      if (cached) {
        metricsCollector.recordCacheLookup(true);
        matchingReports = cached;
      } else {
        metricsCollector.recordCacheLookup(false);
        try {
          matchingReports = await prisma.scamReport.findMany({
            where: {
              OR: targetsToCheck.map((t) => ({
                target: { contains: t },
              })),
            },
            select: {
              id: true,
              scamType: true,
              description: true,
            },
            take: 10,
          });
          this.reportCache.set(cacheKey, matchingReports);
        } catch {
          // Fallback gracefully
        }
      }
    }

    const duration = Date.now() - startTime;
    const reportCount = matchingReports.length;
    let score = 0;
    const indicators: string[] = [];

    if (reportCount > 0) {
      if (reportCount >= 3) {
        score = 85;
      } else if (reportCount >= 2) {
        score = 65;
      } else {
        score = 45;
      }

      for (const rep of matchingReports) {
        indicators.push(`Community Report (${rep.scamType.toUpperCase()}): ${rep.description.slice(0, 100)}...`);
      }
    }

    let severity: DetectorSeverity = 'safe';
    if (score >= 70) severity = 'critical';
    else if (score >= 50) severity = 'high';
    else if (score >= 30) severity = 'medium';
    else if (score > 0) severity = 'low';

    const confidence = reportCount > 0 ? Math.min(95, 75 + reportCount * 10) : 50;

    const summary = reportCount > 0
      ? `Cross-referenced ${reportCount} active community threat reports targeting this identity or link.`
      : `No matching community threat reports found in crowdsourced threat database.`;

    return {
      detector_name: this.name,
      detector_type: this.type,
      score,
      severity,
      confidence,
      evidence: {
        summary,
        indicators,
        details: {
          matched_reports_count: reportCount,
          report_ids: matchingReports.map((r) => r.id),
          categories: Array.from(new Set(matchingReports.map((r) => r.scamType))),
        },
      },
      execution_time_ms: duration,
    };
  }
}

export const communityReportDetector = new CommunityReportDetector();
