/**
 * Performance Monitor & Metrics Collector
 *
 * Provides real-time, low-overhead statistical measurements of:
 * - API response times (p50, p95, p99, min, max, avg, slow requests)
 * - AI latency & cache effectiveness
 * - Database query timings & slow queries
 * - URL analysis timings & redirect hops
 * - File processing timings & engine breakdowns
 * - System memory usage (RSS, Heap, External)
 * - System CPU utilization
 */

import { logger } from '../../utils/logger';

class LatencyRingBuffer {
  private buffer: number[];
  private maxSize: number;
  private pointer = 0;
  private isFull = false;

  constructor(maxSize = 1000) {
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
  api: {
    total_requests: number;
    slow_requests: number;
    error_requests: number;
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
    latency_ms: {
      p50: number;
      p95: number;
      p99: number;
      avg: number;
    };
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
  api_response_time?: any;
  ai_latency?: any;
  database_queries?: any;
}

export class MetricsCollector {
  private static instance: MetricsCollector | null = null;

  // Latency buffers
  private apiLatencies = new LatencyRingBuffer(2000);
  private aiLatencies = new LatencyRingBuffer(500);
  private dbLatencies = new LatencyRingBuffer(2000);
  private urlLatencies = new LatencyRingBuffer(1000);
  private fileLatencies = new LatencyRingBuffer(1000);

  // Counters
  private totalApiRequests = 0;
  private slowApiRequests = 0;
  private errorApiRequests = 0;

  private totalAiCalls = 0;
  private cachedAiCalls = 0;
  private fallbackAiCalls = 0;

  private totalDbQueries = 0;
  private slowDbQueries = 0;

  private totalUrlAnalyses = 0;
  private cachedUrlAnalyses = 0;

  private totalFileAnalyses = 0;
  private cachedFileAnalyses = 0;

  // CPU measurement baseline
  private lastCpuUsage = process.cpuUsage();
  private lastCpuCheck = Date.now();

  private constructor() {}

  public static getInstance(): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector();
    }
    return MetricsCollector.instance;
  }

  // 1. API Request Tracking
  recordApiRequest(durationMs: number, statusCode: number): void {
    this.totalApiRequests++;
    this.apiLatencies.push(durationMs);
    if (durationMs > 1000) this.slowApiRequests++;
    if (statusCode >= 500) this.errorApiRequests++;
  }

  // 2. AI Latency Tracking
  recordAiCall(durationMs: number, isCached: boolean, isFallback = false): void {
    this.totalAiCalls++;
    if (isCached) {
      this.cachedAiCalls++;
    } else {
      this.aiLatencies.push(durationMs);
    }
    if (isFallback) this.fallbackAiCalls++;
  }

  // 3. Database Query Tracking
  recordDbQuery(durationMs: number): void {
    this.totalDbQueries++;
    this.dbLatencies.push(durationMs);
    if (durationMs > 50) this.slowDbQueries++;
  }

  // 4. URL Analysis Tracking
  recordUrlAnalysis(durationMs: number, isCached = false): void {
    this.totalUrlAnalyses++;
    if (isCached) {
      this.cachedUrlAnalyses++;
    } else {
      this.urlLatencies.push(durationMs);
    }
  }

  // 5. File Processing Tracking
  recordFileAnalysis(durationMs: number, isCached = false): void {
    this.totalFileAnalyses++;
    if (isCached) {
      this.cachedFileAnalyses++;
    } else {
      this.fileLatencies.push(durationMs);
    }
  }

  // 6. Report Generation
  getPerformanceMetrics(): PerformanceMetricsReport {
    return this.getSummary();
  }

  getSummary(): PerformanceMetricsReport {
    const mem = process.memoryUsage();
    const currentCpu = process.cpuUsage(this.lastCpuUsage);
    const now = Date.now();
    const elapsedMs = Math.max(1, now - this.lastCpuCheck);

    // Approximate CPU percentage = (user + sys microseconds) / (elapsedMs * 1000 * numCores) * 100
    const totalMicros = currentCpu.user + currentCpu.system;
    const approxCpuPercent = Math.min(100, Math.round((totalMicros / (elapsedMs * 1000)) * 100 * 10) / 10);

    const apiStats = this.apiLatencies.getPercentiles();
    const aiStats = this.aiLatencies.getPercentiles();
    const dbStats = this.dbLatencies.getPercentiles();
    const urlStats = this.urlLatencies.getPercentiles();
    const fileStats = this.fileLatencies.getPercentiles();

    const apiData = {
      total_requests: this.totalApiRequests,
      slow_requests: this.slowApiRequests,
      error_requests: this.errorApiRequests,
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
      latency_ms: {
        p50: dbStats.p50,
        p95: dbStats.p95,
        p99: dbStats.p99,
        avg: dbStats.avg,
      },
    };

    return {
      timestamp: new Date().toISOString(),
      uptime_seconds: Math.floor(process.uptime()),
      api: apiData,
      api_response_time: apiData,
      ai: aiData,
      ai_latency: aiData,
      database: dbData,
      database_queries: dbData,
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
    };
  }

  private alertInterval: NodeJS.Timeout | null = null;

  /**
   * Proactively evaluates system metrics against operational SLO thresholds.
   * Emits structured warnings when thresholds are violated.
   */
  public evaluateThresholdAlerts(): { alerted: boolean; warnings: string[] } {
    const report = this.getSummary();
    const warnings: string[] = [];

    // 1. High Memory Alert (> 400MB heap used)
    if (report.memory.heap_used_mb > 400) {
      const msg = `Heap memory usage exceeded 400MB threshold: ${report.memory.heap_used_mb}MB`;
      warnings.push(msg);
      logger.warn(`[HIGH_MEMORY_USAGE] ${msg}`, {
        event_type: 'HIGH_MEMORY_USAGE',
        heapUsedMb: report.memory.heap_used_mb,
        heapTotalMb: report.memory.heap_total_mb,
      });
    }

    // 2. High API Latency Alert (p99 > 5000ms)
    if (report.api.latency_ms.p99 > 5000) {
      const msg = `API p99 latency exceeded 5,000ms threshold: ${report.api.latency_ms.p99}ms`;
      warnings.push(msg);
      logger.warn(`[HIGH_API_LATENCY] ${msg}`, {
        event_type: 'HIGH_API_LATENCY',
        p99LatencyMs: report.api.latency_ms.p99,
        slowRequests: report.api.slow_requests,
      });
    }

    // 3. AI Service Degradation Alert (AI fallback requests > 5 and failure rate > 50%)
    const totalAi = report.ai.total_calls;
    const failedAi = report.ai.fallback_calls;
    if (totalAi >= 5 && (failedAi / totalAi) > 0.5) {
      const msg = `AI service degraded: ${failedAi}/${totalAi} requests triggered fallback (${Math.round((failedAi / totalAi) * 100)}%)`;
      warnings.push(msg);
      logger.warn(`[AI_SERVICE_DEGRADED] ${msg}`, {
        event_type: 'AI_SERVICE_DEGRADED',
        totalAiCalls: totalAi,
        failedAiCalls: failedAi,
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
