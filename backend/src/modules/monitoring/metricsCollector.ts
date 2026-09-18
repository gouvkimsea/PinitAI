/**
 * Performance Monitor & Metrics Collector
 *
 * Provides real-time, low-overhead statistical measurements of:
 * - Scans: Total scans, scans by input type, detection categories, risk & confidence distribution
 * - Reliability: False-positive and false-negative counts and rates
 * - Latencies: API response times (avg, p50, p95, p99, min, max, slow requests)
 * - Subsystems: AI usage & failures, external API calls & failures, database queries & failures
 * - Cache: Hit/miss rate and lookup counts
 * - Queue: Failures, attempts, active jobs
 * - Errors: Timeout rate, overall error rate
 * - Resources: System memory usage (RSS, Heap) and CPU utilization
 */

import { logger } from '../../utils/logger';

class LatencyRingBuffer {
  private buffer: number[];
  private maxSize: number;
  private pointer = 0;
  private isFull = false;

  constructor(maxSize = 2000) {
    this.maxSize = maxSize;
    this.buffer = new Array(maxSize);
  }

  push(val: number): void {
    this.buffer[this.pointer] = val;
    this.pointer = (this.pointer + 1) % this.maxSize;
    if (this.pointer === 0) this.isFull = true;
  }

  getValues(): number[] {
    const count = this.isFull ? this.maxSize : this.pointer;
    return this.buffer.slice(0, count);
  }

  getPercentiles(): { p50: number; p95: number; p99: number; min: number; max: number; avg: number; count: number } {
    const values = this.getValues();
    if (values.length === 0) {
      return { p50: 0, p95: 0, p99: 0, min: 0, max: 0, avg: 0, count: 0 };
    }

    values.sort((a, b) => a - b);
    const count = values.length;
    const sum = values.reduce((acc, v) => acc + v, 0);

    const p50 = values[Math.floor(count * 0.5)];
    const p95 = values[Math.min(count - 1, Math.floor(count * 0.95))];
    const p99 = values[Math.min(count - 1, Math.floor(count * 0.99))];
    const min = values[0];
    const max = values[count - 1];
    const avg = Math.round((sum / count) * 100) / 100;

    return { p50, p95, p99, min, max, avg, count };
  }
}

export interface PerformanceMetricsReport {
  timestamp: string;
  uptime_seconds: number;
  scans: {
    total_scans: number;
    scans_by_input_type: Record<string, number>;
    detection_categories: Record<string, number>;
    risk_distribution: {
      SAFE: number;
      SUSPICIOUS: number;
      HIGH_RISK: number;
      MALICIOUS: number;
    };
    confidence_distribution: {
      low: number;
      medium: number;
      high: number;
    };
    detection_failures: number;
    detection_failure_rate_percent: number;
  };
  feedback: {
    false_positives: number;
    false_negatives: number;
    false_positive_rate_percent: number;
    false_negative_rate_percent: number;
  };
  api: {
    total_requests: number;
    slow_requests: number;
    error_requests: number;
    timeout_requests: number;
    error_rate_percent: number;
    timeout_rate_percent: number;
    latency_ms: {
      p50: number;
      p95: number;
      p99: number;
      avg: number;
      min: number;
      max: number;
    };
  };
  ai: {
    total_calls: number;
    cached_calls: number;
    cache_hit_rate_percent: number;
    fallback_calls: number;
    failure_calls: number;
    failure_rate_percent: number;
    latency_ms: {
      p50: number;
      p95: number;
      p99: number;
      avg: number;
    };
  };
  database: {
    total_queries: number;
    slow_queries: number;
    failure_queries: number;
    failure_rate_percent: number;
    latency_ms: {
      p50: number;
      p95: number;
      p99: number;
      avg: number;
    };
  };
  external_api: {
    total_calls: number;
    failure_calls: number;
    failure_rate_percent: number;
    latency_ms: {
      p50: number;
      p95: number;
      p99: number;
      avg: number;
    };
  };
  queue: {
    total_enqueued: number;
    failures: number;
    failure_rate_percent: number;
  };
  cache: {
    total_lookups: number;
    total_hits: number;
    total_misses: number;
    hit_rate_percent: number;
  };
  url_analysis: {
    total_analyses: number;
    cached_analyses: number;
    cache_hit_rate_percent: number;
    latency_ms: {
      p50: number;
      p95: number;
      p99: number;
      avg: number;
    };
  };
  file_processing: {
    total_files: number;
    cached_files: number;
    cache_hit_rate_percent: number;
    latency_ms: {
      p50: number;
      p95: number;
      p99: number;
      avg: number;
    };
  };
  memory: {
    rss_mb: number;
    heap_used_mb: number;
    heap_total_mb: number;
    external_mb: number;
  };
  cpu: {
    user_cpu_ms: number;
    system_cpu_ms: number;
    approx_cpu_percent: number;
  };
  concurrency: {
    active_requests: number;
    peak_concurrent_requests: number;
  };

  // Backward compatibility aliases
  api_response_time?: any;
  ai_latency?: any;
  database_queries?: any;
  external_api_latency?: any;
  concurrent_requests?: any;
  cache_hit_rate?: any;
}

export class MetricsCollector {
  private static instance: MetricsCollector | null = null;

  // Latency buffers
  private apiLatencies = new LatencyRingBuffer(2000);
  private aiLatencies = new LatencyRingBuffer(500);
  private dbLatencies = new LatencyRingBuffer(2000);
  private urlLatencies = new LatencyRingBuffer(1000);
  private fileLatencies = new LatencyRingBuffer(1000);
  private externalApiLatencies = new LatencyRingBuffer(1000);

  // Scan & Detection Telemetry
  private totalScans = 0;
  private scansByInputType: Record<string, number> = { TEXT: 0, URL: 0, FILE: 0, QR: 0 };
  private detectionCategories: Record<string, number> = {};
  private riskDistribution = { SAFE: 0, SUSPICIOUS: 0, HIGH_RISK: 0, MALICIOUS: 0 };
  private confidenceDistribution = { low: 0, medium: 0, high: 0 };
  private detectionFailures = 0;

  // Feedback Tracking (False-Positives & False-Negatives)
  private falsePositives = 0;
  private falseNegatives = 0;

  // API Counters
  private totalApiRequests = 0;
  private slowApiRequests = 0;
  private errorApiRequests = 0;
  private timeoutRequests = 0;

  // AI Counters
  private totalAiCalls = 0;
  private cachedAiCalls = 0;
  private fallbackAiCalls = 0;
  private failedAiCalls = 0;

  // Database Counters
  private totalDbQueries = 0;
  private slowDbQueries = 0;
  private failedDbQueries = 0;

  // External API Counters
  private totalExternalApiCalls = 0;
  private failedExternalApiCalls = 0;

  // Queue Counters
  private queueEnqueued = 0;
  private queueFailures = 0;

  // Cache Counters
  private totalCacheLookups = 0;
  private totalCacheHits = 0;

  // URL & File Analysis Specific Counters
  private totalUrlAnalyses = 0;
  private cachedUrlAnalyses = 0;
  private totalFileAnalyses = 0;
  private cachedFileAnalyses = 0;

  // Concurrency Tracking
  private activeRequests = 0;
  private peakConcurrentRequests = 0;

  // Baseline for traffic spike alert detection
  private lastRequestCountForSpike = 0;
  private lastSpikeCheckTime = Date.now();
  private lastFpRateForAlert = 0;
  private lastFnRateForAlert = 0;

  // CPU measurement baseline
  private lastCpuUsage = process.cpuUsage();
  private lastCpuCheck = Date.now();

  private alertInterval: NodeJS.Timeout | null = null;

  private constructor() {}

  public static getInstance(): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector();
    }
    return MetricsCollector.instance;
  }

  // Reset all counters and buffers (useful for testing and benchmarking)
  reset(): void {
    this.apiLatencies = new LatencyRingBuffer(2000);
    this.aiLatencies = new LatencyRingBuffer(500);
    this.dbLatencies = new LatencyRingBuffer(2000);
    this.urlLatencies = new LatencyRingBuffer(1000);
    this.fileLatencies = new LatencyRingBuffer(1000);
    this.externalApiLatencies = new LatencyRingBuffer(1000);

    this.totalScans = 0;
    this.scansByInputType = { TEXT: 0, URL: 0, FILE: 0, QR: 0 };
    this.detectionCategories = {};
    this.riskDistribution = { SAFE: 0, SUSPICIOUS: 0, HIGH_RISK: 0, MALICIOUS: 0 };
    this.confidenceDistribution = { low: 0, medium: 0, high: 0 };
    this.detectionFailures = 0;

    this.falsePositives = 0;
    this.falseNegatives = 0;

    this.totalApiRequests = 0;
    this.slowApiRequests = 0;
    this.errorApiRequests = 0;
    this.timeoutRequests = 0;

    this.totalAiCalls = 0;
    this.cachedAiCalls = 0;
    this.fallbackAiCalls = 0;
    this.failedAiCalls = 0;

    this.totalDbQueries = 0;
    this.slowDbQueries = 0;
    this.failedDbQueries = 0;

    this.totalExternalApiCalls = 0;
    this.failedExternalApiCalls = 0;

    this.queueEnqueued = 0;
    this.queueFailures = 0;

    this.totalCacheLookups = 0;
    this.totalCacheHits = 0;

    this.totalUrlAnalyses = 0;
    this.cachedUrlAnalyses = 0;
    this.totalFileAnalyses = 0;
    this.cachedFileAnalyses = 0;

    this.activeRequests = 0;
    this.peakConcurrentRequests = 0;

    this.lastRequestCountForSpike = 0;
    this.lastSpikeCheckTime = Date.now();
    this.lastFpRateForAlert = 0;
    this.lastFnRateForAlert = 0;

    this.lastCpuUsage = process.cpuUsage();
    this.lastCpuCheck = Date.now();
  }

  // -------------------------------------------------------------------------
  // 1. Scan & Detection Tracking
  // -------------------------------------------------------------------------
  recordScan(params: {
    inputType: string;
    threatCategory?: string;
    threatLevel?: string;
    confidenceScore?: number;
  }): void {
    this.totalScans++;

    const normType = (params.inputType || 'TEXT').toUpperCase();
    this.scansByInputType[normType] = (this.scansByInputType[normType] || 0) + 1;

    if (params.threatCategory) {
      const cat = params.threatCategory;
      this.detectionCategories[cat] = (this.detectionCategories[cat] || 0) + 1;
    }

    const level = (params.threatLevel || 'SAFE').toUpperCase() as keyof typeof this.riskDistribution;
    if (this.riskDistribution[level] !== undefined) {
      this.riskDistribution[level]++;
    } else {
      this.riskDistribution.SAFE++;
    }

    const conf = params.confidenceScore ?? 50;
    if (conf >= 80) {
      this.confidenceDistribution.high++;
    } else if (conf >= 50) {
      this.confidenceDistribution.medium++;
    } else {
      this.confidenceDistribution.low++;
    }
  }

  recordDetectionFailure(): void {
    this.detectionFailures++;
  }

  // -------------------------------------------------------------------------
  // 2. Feedback Tracking (False-Positives & False-Negatives)
  // -------------------------------------------------------------------------
  recordFalsePositive(): void {
    this.falsePositives++;
  }

  recordFalseNegative(): void {
    this.falseNegatives++;
  }

  // -------------------------------------------------------------------------
  // 3. API Request & Latency Tracking
  // -------------------------------------------------------------------------
  recordApiRequest(durationMs: number, statusCode: number): void {
    this.totalApiRequests++;
    this.apiLatencies.push(durationMs);
    if (durationMs > 1000) this.slowApiRequests++;
    if (statusCode >= 500) this.errorApiRequests++;
    if (statusCode === 504) this.timeoutRequests++;
  }

  recordTimeout(): void {
    this.timeoutRequests++;
  }

  // -------------------------------------------------------------------------
  // 4. AI Latency & Usage Tracking
  // -------------------------------------------------------------------------
  recordAiCall(durationMs: number, isCached: boolean, isFallback = false, isFailure = false): void {
    this.totalAiCalls++;
    if (isCached) {
      this.cachedAiCalls++;
    } else {
      this.aiLatencies.push(durationMs);
    }
    if (isFallback) this.fallbackAiCalls++;
    if (isFailure) this.failedAiCalls++;
  }

  // -------------------------------------------------------------------------
  // 5. Database Tracking
  // -------------------------------------------------------------------------
  recordDbQuery(durationMs: number, success = true): void {
    this.totalDbQueries++;
    this.dbLatencies.push(durationMs);
    if (durationMs > 50) this.slowDbQueries++;
    if (!success) this.failedDbQueries++;
  }

  recordDbFailure(): void {
    this.failedDbQueries++;
  }

  // -------------------------------------------------------------------------
  // 6. External API Tracking
  // -------------------------------------------------------------------------
  recordExternalApiCall(durationMs: number, success = true): void {
    this.totalExternalApiCalls++;
    this.externalApiLatencies.push(durationMs);
    if (!success) this.failedExternalApiCalls++;
  }

  // -------------------------------------------------------------------------
  // 7. Queue Tracking
  // -------------------------------------------------------------------------
  recordQueueEnqueued(): void {
    this.queueEnqueued++;
  }

  recordQueueFailure(): void {
    this.queueFailures++;
  }

  // -------------------------------------------------------------------------
  // 8. Cache Tracking
  // -------------------------------------------------------------------------
  recordCacheLookup(hit: boolean): void {
    this.totalCacheLookups++;
    if (hit) this.totalCacheHits++;
  }

  recordCacheHit(): void {
    this.recordCacheLookup(true);
  }

  recordCacheMiss(): void {
    this.recordCacheLookup(false);
  }

  // -------------------------------------------------------------------------
  // 9. URL & File Processing Tracking
  // -------------------------------------------------------------------------
  recordUrlAnalysis(durationMs: number, isCached = false): void {
    this.totalUrlAnalyses++;
    if (isCached) {
      this.cachedUrlAnalyses++;
    } else {
      this.urlLatencies.push(durationMs);
    }
  }

  recordFileAnalysis(durationMs: number, isCached = false): void {
    this.totalFileAnalyses++;
    if (isCached) {
      this.cachedFileAnalyses++;
    } else {
      this.fileLatencies.push(durationMs);
    }
  }

  // -------------------------------------------------------------------------
  // 10. Concurrency Tracking
  // -------------------------------------------------------------------------
  incrementActiveRequests(): void {
    this.activeRequests++;
    if (this.activeRequests > this.peakConcurrentRequests) {
      this.peakConcurrentRequests = this.activeRequests;
    }
  }

  decrementActiveRequests(): void {
    if (this.activeRequests > 0) this.activeRequests--;
  }

  // -------------------------------------------------------------------------
  // 11. Report Generation
  // -------------------------------------------------------------------------
  getPerformanceMetrics(): PerformanceMetricsReport {
    return this.getSummary();
  }

  getSummary(): PerformanceMetricsReport {
    const mem = process.memoryUsage();
    const currentCpu = process.cpuUsage(this.lastCpuUsage);
    const now = Date.now();
    const elapsedMs = Math.max(1, now - this.lastCpuCheck);

    const totalMicros = currentCpu.user + currentCpu.system;
    const approxCpuPercent = Math.min(100, Math.round((totalMicros / (elapsedMs * 1000)) * 100 * 10) / 10);

    const apiStats = this.apiLatencies.getPercentiles();
    const aiStats = this.aiLatencies.getPercentiles();
    const dbStats = this.dbLatencies.getPercentiles();
    const urlStats = this.urlLatencies.getPercentiles();
    const fileStats = this.fileLatencies.getPercentiles();
    const extStats = this.externalApiLatencies.getPercentiles();

    // Rates calculation
    const totalReqs = this.totalApiRequests;
    const errorRatePercent = totalReqs > 0
      ? Math.round((this.errorApiRequests / totalReqs) * 10000) / 100
      : 0;
    const timeoutRatePercent = totalReqs > 0
      ? Math.round((this.timeoutRequests / totalReqs) * 10000) / 100
      : 0;

    const totalScansCount = this.totalScans;
    const detectionFailureRatePercent = totalScansCount > 0
      ? Math.round((this.detectionFailures / totalScansCount) * 10000) / 100
      : 0;
    const fpRatePercent = totalScansCount > 0
      ? Math.round((this.falsePositives / totalScansCount) * 10000) / 100
      : 0;
    const fnRatePercent = totalScansCount > 0
      ? Math.round((this.falseNegatives / totalScansCount) * 10000) / 100
      : 0;

    const aiFailureRatePercent = this.totalAiCalls > 0
      ? Math.round(((this.failedAiCalls + this.fallbackAiCalls) / this.totalAiCalls) * 10000) / 100
      : 0;

    const dbFailureRatePercent = this.totalDbQueries > 0
      ? Math.round((this.failedDbQueries / this.totalDbQueries) * 10000) / 100
      : 0;

    const extFailureRatePercent = this.totalExternalApiCalls > 0
      ? Math.round((this.failedExternalApiCalls / this.totalExternalApiCalls) * 10000) / 100
      : 0;

    const queueFailureRatePercent = this.queueEnqueued > 0
      ? Math.round((this.queueFailures / this.queueEnqueued) * 10000) / 100
      : 0;

    const totalMisses = Math.max(0, this.totalCacheLookups - this.totalCacheHits);
    const cacheHitRatePercent = this.totalCacheLookups > 0
      ? Math.round((this.totalCacheHits / this.totalCacheLookups) * 10000) / 100
      : 0;

    const apiData = {
      total_requests: this.totalApiRequests,
      slow_requests: this.slowApiRequests,
      error_requests: this.errorApiRequests,
      timeout_requests: this.timeoutRequests,
      error_rate_percent: errorRatePercent,
      timeout_rate_percent: timeoutRatePercent,
      latency_ms: {
        p50: apiStats.p50,
        p95: apiStats.p95,
        p99: apiStats.p99,
        avg: apiStats.avg,
        min: apiStats.min,
        max: apiStats.max,
      },
    };

    const aiData = {
      total_calls: this.totalAiCalls,
      cached_calls: this.cachedAiCalls,
      cache_hit_rate_percent: this.totalAiCalls > 0
        ? Math.round((this.cachedAiCalls / this.totalAiCalls) * 10000) / 100
        : 0,
      fallback_calls: this.fallbackAiCalls,
      failure_calls: this.failedAiCalls,
      failure_rate_percent: aiFailureRatePercent,
      latency_ms: {
        p50: aiStats.p50,
        p95: aiStats.p95,
        p99: aiStats.p99,
        avg: aiStats.avg,
      },
    };

    const dbData = {
      total_queries: this.totalDbQueries,
      slow_queries: this.slowDbQueries,
      failure_queries: this.failedDbQueries,
      failure_rate_percent: dbFailureRatePercent,
      latency_ms: {
        p50: dbStats.p50,
        p95: dbStats.p95,
        p99: dbStats.p99,
        avg: dbStats.avg,
      },
    };

    const externalApiData = {
      total_calls: this.totalExternalApiCalls,
      failure_calls: this.failedExternalApiCalls,
      failure_rate_percent: extFailureRatePercent,
      latency_ms: {
        p50: extStats.p50,
        p95: extStats.p95,
        p99: extStats.p99,
        avg: extStats.avg,
      },
    };

    const queueData = {
      total_enqueued: this.queueEnqueued,
      failures: this.queueFailures,
      failure_rate_percent: queueFailureRatePercent,
    };

    const cacheData = {
      total_lookups: this.totalCacheLookups,
      total_hits: this.totalCacheHits,
      total_misses: totalMisses,
      hit_rate_percent: cacheHitRatePercent,
    };

    const scansData = {
      total_scans: this.totalScans,
      scans_by_input_type: { ...this.scansByInputType },
      detection_categories: { ...this.detectionCategories },
      risk_distribution: { ...this.riskDistribution },
      confidence_distribution: { ...this.confidenceDistribution },
      detection_failures: this.detectionFailures,
      detection_failure_rate_percent: detectionFailureRatePercent,
    };

    const feedbackData = {
      false_positives: this.falsePositives,
      false_negatives: this.falseNegatives,
      false_positive_rate_percent: fpRatePercent,
      false_negative_rate_percent: fnRatePercent,
    };

    const concurrencyData = {
      active_requests: this.activeRequests,
      peak_concurrent_requests: this.peakConcurrentRequests,
    };

    return {
      timestamp: new Date().toISOString(),
      uptime_seconds: Math.floor(process.uptime()),
      scans: scansData,
      feedback: feedbackData,
      api: apiData,
      ai: aiData,
      database: dbData,
      external_api: externalApiData,
      queue: queueData,
      cache: cacheData,
      url_analysis: {
        total_analyses: this.totalUrlAnalyses,
        cached_analyses: this.cachedUrlAnalyses,
        cache_hit_rate_percent: this.totalUrlAnalyses > 0
          ? Math.round((this.cachedUrlAnalyses / this.totalUrlAnalyses) * 10000) / 100
          : 0,
        latency_ms: {
          p50: urlStats.p50,
          p95: urlStats.p95,
          p99: urlStats.p99,
          avg: urlStats.avg,
        },
      },
      file_processing: {
        total_files: this.totalFileAnalyses,
        cached_files: this.cachedFileAnalyses,
        cache_hit_rate_percent: this.totalFileAnalyses > 0
          ? Math.round((this.cachedFileAnalyses / this.totalFileAnalyses) * 10000) / 100
          : 0,
        latency_ms: {
          p50: fileStats.p50,
          p95: fileStats.p95,
          p99: fileStats.p99,
          avg: fileStats.avg,
        },
      },
      memory: {
        rss_mb: Math.round(mem.rss / 1024 / 1024),
        heap_used_mb: Math.round(mem.heapUsed / 1024 / 1024),
        heap_total_mb: Math.round(mem.heapTotal / 1024 / 1024),
        external_mb: Math.round(mem.external / 1024 / 1024),
      },
      cpu: {
        user_cpu_ms: Math.round(currentCpu.user / 1000),
        system_cpu_ms: Math.round(currentCpu.system / 1000),
        approx_cpu_percent: approxCpuPercent,
      },
      concurrency: concurrencyData,

      // Aliases for backward compatibility
      api_response_time: apiData,
      ai_latency: aiData,
      database_queries: dbData,
      external_api_latency: externalApiData,
      concurrent_requests: concurrencyData,
      cache_hit_rate: cacheData,
    };
  }

  // -------------------------------------------------------------------------
  // 12. Automated Alert Evaluation
  // -------------------------------------------------------------------------
  /**
   * Proactively evaluates system metrics against operational alerts:
   * - sudden detection failures
   * - abnormal latency (p95 > 2500ms or p99 > 5000ms)
   * - external API failures (> 30% failure rate with >= 5 calls)
   * - database failures (> 0 failures or > 10% failure rate)
   * - AI failures (> 30% fallback/failure rate with >= 5 calls)
   * - unusual traffic spikes (> 300% increase over previous interval)
   * - sudden changes in false-positive/negative rates (> 15% rate)
   */
  public evaluateThresholdAlerts(): { alerted: boolean; warnings: string[] } {
    const report = this.getSummary();
    const warnings: string[] = [];

    // 1. Sudden Detection Failures
    if (report.scans.detection_failures > 0 && report.scans.detection_failure_rate_percent > 10) {
      const msg = `Detection failure rate critical: ${report.scans.detection_failures} failures (${report.scans.detection_failure_rate_percent}%)`;
      warnings.push(msg);
      logger.warn(`[ALERT_DETECTION_FAILURES] ${msg}`, {
        event_type: 'ALERT_DETECTION_FAILURES',
        detectionFailures: report.scans.detection_failures,
        detectionFailureRate: report.scans.detection_failure_rate_percent,
      });
    }

    // 2. Abnormal Latency Alert (p95 > 2500ms or p99 > 5000ms)
    if (report.api.latency_ms.p99 > 5000 || report.api.latency_ms.p95 > 2500) {
      const msg = `Abnormal API latency detected: p95=${report.api.latency_ms.p95}ms, p99=${report.api.latency_ms.p99}ms`;
      warnings.push(msg);
      logger.warn(`[ALERT_ABNORMAL_LATENCY] ${msg}`, {
        event_type: 'ALERT_ABNORMAL_LATENCY',
        p95: report.api.latency_ms.p95,
        p99: report.api.latency_ms.p99,
        slowRequests: report.api.slow_requests,
      });
    }

    // 3. External API Failures Alert
    if (report.external_api.total_calls >= 5 && report.external_api.failure_rate_percent > 30) {
      const msg = `External API service failure alert: ${report.external_api.failure_calls}/${report.external_api.total_calls} failed (${report.external_api.failure_rate_percent}%)`;
      warnings.push(msg);
      logger.warn(`[ALERT_EXTERNAL_API_FAILURES] ${msg}`, {
        event_type: 'ALERT_EXTERNAL_API_FAILURES',
        totalCalls: report.external_api.total_calls,
        failureCalls: report.external_api.failure_calls,
        failureRate: report.external_api.failure_rate_percent,
      });
    }

    // 4. Database Failures Alert
    if (report.database.failure_queries > 0) {
      const msg = `Database query failures detected: ${report.database.failure_queries} failed queries (${report.database.failure_rate_percent}%)`;
      warnings.push(msg);
      logger.error(`[ALERT_DATABASE_FAILURES] ${msg}`, {
        event_type: 'ALERT_DATABASE_FAILURES',
        failureQueries: report.database.failure_queries,
        totalQueries: report.database.total_queries,
      });
    }

    // 5. AI Service Degradation & Failures Alert
    const totalAi = report.ai.total_calls;
    const failedAi = report.ai.failure_calls + report.ai.fallback_calls;
    if (totalAi >= 5 && (failedAi / totalAi) > 0.3) {
      const rate = Math.round((failedAi / totalAi) * 100);
      const msg = `AI service degradation alert: ${failedAi}/${totalAi} calls triggered fallback or failed (${rate}%)`;
      warnings.push(msg);
      logger.warn(`[ALERT_AI_FAILURES] ${msg}`, {
        event_type: 'ALERT_AI_FAILURES',
        totalAiCalls: totalAi,
        failedAiCalls: failedAi,
        failureRate: rate,
      });
    }

    // 6. Traffic Spike Alert (> 300% request volume surge)
    const currentRequests = report.api.total_requests;
    const deltaReq = currentRequests - this.lastRequestCountForSpike;
    const now = Date.now();
    const elapsedSpikeSeconds = Math.max(1, (now - this.lastSpikeCheckTime) / 1000);

    if (this.lastRequestCountForSpike > 10 && deltaReq > this.lastRequestCountForSpike * 3) {
      const msg = `Unusual traffic spike detected: +${deltaReq} requests in ${Math.round(elapsedSpikeSeconds)}s (Surge of ${Math.round((deltaReq / this.lastRequestCountForSpike) * 100)}%)`;
      warnings.push(msg);
      logger.warn(`[ALERT_TRAFFIC_SPIKE] ${msg}`, {
        event_type: 'ALERT_TRAFFIC_SPIKE',
        previousRequests: this.lastRequestCountForSpike,
        currentRequests,
        surgeCount: deltaReq,
      });
    }
    this.lastRequestCountForSpike = currentRequests;
    this.lastSpikeCheckTime = now;

    // 7. Sudden Changes in False-Positive / False-Negative Rates
    if (report.feedback.false_positive_rate_percent > 15 && Math.abs(report.feedback.false_positive_rate_percent - this.lastFpRateForAlert) >= 5) {
      const msg = `Sudden surge in false-positive reports: ${report.feedback.false_positive_rate_percent}% (previously ${this.lastFpRateForAlert}%)`;
      warnings.push(msg);
      logger.warn(`[ALERT_FP_RATE_SURGE] ${msg}`, {
        event_type: 'ALERT_FP_RATE_SURGE',
        currentRate: report.feedback.false_positive_rate_percent,
        previousRate: this.lastFpRateForAlert,
      });
      this.lastFpRateForAlert = report.feedback.false_positive_rate_percent;
    }

    if (report.feedback.false_negative_rate_percent > 15 && Math.abs(report.feedback.false_negative_rate_percent - this.lastFnRateForAlert) >= 5) {
      const msg = `Sudden surge in false-negative reports: ${report.feedback.false_negative_rate_percent}% (previously ${this.lastFnRateForAlert}%)`;
      warnings.push(msg);
      logger.warn(`[ALERT_FN_RATE_SURGE] ${msg}`, {
        event_type: 'ALERT_FN_RATE_SURGE',
        currentRate: report.feedback.false_negative_rate_percent,
        previousRate: this.lastFnRateForAlert,
      });
      this.lastFnRateForAlert = report.feedback.false_negative_rate_percent;
    }

    // 8. High Memory Alert (> 400MB heap used)
    if (report.memory.heap_used_mb > 400) {
      const msg = `Heap memory usage exceeded 400MB threshold: ${report.memory.heap_used_mb}MB`;
      warnings.push(msg);
      logger.warn(`[HIGH_MEMORY_USAGE] ${msg}`, {
        event_type: 'HIGH_MEMORY_USAGE',
        heapUsedMb: report.memory.heap_used_mb,
        heapTotalMb: report.memory.heap_total_mb,
      });
    }

    return { alerted: warnings.length > 0, warnings };
  }

  /**
   * Starts periodic background threshold evaluation.
   */
  public startHealthAlerts(intervalMs = 60000): void {
    if (this.alertInterval) return;
    this.alertInterval = setInterval(() => {
      this.evaluateThresholdAlerts();
    }, intervalMs);
    this.alertInterval.unref();
    logger.info('Continuous system health alerting initialized');
  }

  public stopHealthAlerts(): void {
    if (this.alertInterval) {
      clearInterval(this.alertInterval);
      this.alertInterval = null;
    }
  }
}

export const metricsCollector = MetricsCollector.getInstance();
