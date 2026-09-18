import {
  SampleEvaluationResult,
  ConfusionMatrix,
  LatencyStats,
  PerformanceMetrics,
  ComprehensiveEvaluationReport,
  SampleLanguage,
  DifficultyLevel,
} from './dataset/types';

export class MetricsCalculator {
  /**
   * Computes standard confusion matrix and classification metrics from sample results.
   */
  public calculatePerformance(results: SampleEvaluationResult[]): PerformanceMetrics {
    const total = results.length;
    if (total === 0) {
      return {
        total: 0,
        confusionMatrix: { truePositives: 0, trueNegatives: 0, falsePositives: 0, falseNegatives: 0 },
        accuracy: 100,
        precision: 100,
        recall: 100,
        f1Score: 100,
        falsePositiveRate: 0,
        falseNegativeRate: 0,
      };
    }

    let tp = 0;
    let tn = 0;
    let fp = 0;
    let fn = 0;

    for (const r of results) {
      if (r.expectedLabel === 'SCAM') {
        if (r.predictedLabel === 'SCAM') {
          tp++;
        } else {
          fn++;
        }
      } else {
        if (r.predictedLabel === 'LEGITIMATE') {
          tn++;
        } else {
          fp++;
        }
      }
    }

    const confusionMatrix: ConfusionMatrix = {
      truePositives: tp,
      trueNegatives: tn,
      falsePositives: fp,
      falseNegatives: fn,
    };

    const accuracy = ((tp + tn) / total) * 100;
    const precision = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 100;
    const recall = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 100;
    const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const falsePositiveRate = fp + tn > 0 ? (fp / (fp + tn)) * 100 : 0;
    const falseNegativeRate = tp + fn > 0 ? (fn / (tp + fn)) * 100 : 0;

    return {
      total,
      confusionMatrix,
      accuracy: Math.round(accuracy * 100) / 100,
      precision: Math.round(precision * 100) / 100,
      recall: Math.round(recall * 100) / 100,
      f1Score: Math.round(f1Score * 100) / 100,
      falsePositiveRate: Math.round(falsePositiveRate * 100) / 100,
      falseNegativeRate: Math.round(falseNegativeRate * 100) / 100,
    };
  }

  /**
   * Computes latency distribution statistics across evaluated samples.
   */
  public calculateLatencyStats(results: SampleEvaluationResult[]): LatencyStats {
    if (results.length === 0) {
      return { meanMs: 0, medianMs: 0, p90Ms: 0, p95Ms: 0, p99Ms: 0, minMs: 0, maxMs: 0 };
    }

    const latencies = results.map((r) => r.latencyMs).sort((a, b) => a - b);
    const count = latencies.length;
    const sum = latencies.reduce((acc, val) => acc + val, 0);
    const meanMs = Math.round((sum / count) * 10) / 10;

    const getPercentile = (p: number) => {
      const idx = Math.min(count - 1, Math.floor((p / 100) * count));
      return latencies[idx];
    };

    return {
      meanMs,
      medianMs: getPercentile(50),
      p90Ms: getPercentile(90),
      p95Ms: getPercentile(95),
      p99Ms: getPercentile(99),
      minMs: latencies[0],
      maxMs: latencies[count - 1],
    };
  }

  /**
   * Assembles a comprehensive benchmark evaluation report with multi-dimensional breakdowns.
   */
  public generateComprehensiveReport(
    results: SampleEvaluationResult[],
    totalDurationMs: number
  ): ComprehensiveEvaluationReport {
    const overallPerformance = this.calculatePerformance(results);
    const latencyStats = this.calculateLatencyStats(results);

    // Language Breakdown
    const languages: SampleLanguage[] = ['en', 'km', 'km-en'];
    const languageBreakdown: Record<SampleLanguage, PerformanceMetrics> = {} as any;
    for (const lang of languages) {
      const subset = results.filter((r) => r.language === lang);
      languageBreakdown[lang] = this.calculatePerformance(subset);
    }

    // Category Breakdown
    const categories = Array.from(new Set(results.map((r) => r.category)));
    const categoryBreakdown: Record<string, PerformanceMetrics> = {};
    for (const cat of categories) {
      const subset = results.filter((r) => r.category === cat);
      categoryBreakdown[cat] = this.calculatePerformance(subset);
    }

    // Difficulty Breakdown
    const difficulties: DifficultyLevel[] = ['obvious', 'subtle', 'adversarial'];
    const difficultyBreakdown: Record<DifficultyLevel, PerformanceMetrics> = {} as any;
    for (const diff of difficulties) {
      const subset = results.filter((r) => r.difficulty === diff);
      difficultyBreakdown[diff] = this.calculatePerformance(subset);
    }

    // Nuance Breakdown
    const nuanceBreakdown: Record<string, PerformanceMetrics> = {};
    const allTags = Array.from(new Set(results.flatMap((r) => r.nuanceTags)));
    for (const tag of allTags) {
      const subset = results.filter((r) => r.nuanceTags.includes(tag));
      nuanceBreakdown[tag] = this.calculatePerformance(subset);
    }

    // Security Audit & Safety Gate
    // High-consequence threats (OTP theft, credential theft, malware download, fake banking) must NEVER produce false negatives!
    const criticalCategories = new Set(['otp_theft', 'credential_theft', 'malicious_download', 'fake_banking']);
    const criticalFalseNegatives = results.filter(
      (r) => r.isFalseNegative && criticalCategories.has(r.category)
    );

    const gateFailures: string[] = [];
    if (criticalFalseNegatives.length > 0) {
      gateFailures.push(
        `Critical threat false negatives detected (${criticalFalseNegatives.length} cases): [${criticalFalseNegatives.map((c) => c.sampleId).join(', ')}]`
      );
    }
    if (overallPerformance.falseNegativeRate > 5.0) {
      gateFailures.push(`Overall False Negative Rate exceeded 5.0% threshold: ${overallPerformance.falseNegativeRate}%`);
    }
    if (overallPerformance.falsePositiveRate > 5.0) {
      gateFailures.push(`Overall False Positive Rate exceeded 5.0% threshold: ${overallPerformance.falsePositiveRate}%`);
    }
    if (overallPerformance.f1Score < 95.0) {
      gateFailures.push(`Overall F1 Score fell below 95.0% threshold: ${overallPerformance.f1Score}%`);
    }

    return {
      ...overallPerformance,
      timestamp: new Date().toISOString(),
      durationMs: totalDurationMs,
      latency: latencyStats,
      languageBreakdown,
      categoryBreakdown,
      difficultyBreakdown,
      nuanceBreakdown,
      securityAudit: {
        criticalFalseNegativesCount: criticalFalseNegatives.length,
        flaggedThreatsSampleIds: criticalFalseNegatives.map((c) => c.sampleId),
        passedSecurityGate: gateFailures.length === 0,
        gateFailures,
      },
      sampleResults: results,
    };
  }
}

export const metricsCalculator = new MetricsCalculator();
