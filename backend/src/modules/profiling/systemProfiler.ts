import fs from 'fs';
import { performance } from 'perf_hooks';
import { detectionPipeline } from '../../pipeline/orchestrator';
import { urlIntelligence } from '../url/urlIntelligence';
import { secureFileAnalyzer, quarantineStorage } from '../file';
import { metricsCollector, PerformanceMetricsReport } from '../monitoring/metricsCollector';

export interface ProfilerResult {
  timestamp: string;
  durationSeconds: number;
  apiResponseTime: {
    meanMs: number;
    p95Ms: number;
    p99Ms: number;
    samples: number;
  };
  databaseQueries: {
    meanMs: number;
    p95Ms: number;
    p99Ms: number;
    totalQueries: number;
  };
  aiLatency: {
    meanMs: number;
    p95Ms: number;
    p99Ms: number;
    totalCalls: number;
    cachedCalls: number;
    cacheHitRatePercent: number;
  };
  externalApi: {
    meanMs: number;
    p95Ms: number;
    p99Ms: number;
    totalCalls: number;
  };
  urlScanningTime: {
    meanMs: number;
    p95Ms: number;
    p99Ms: number;
    scansCount: number;
  };
  fileScanningTime: {
    meanMs: number;
    p95Ms: number;
    p99Ms: number;
    scansCount: number;
  };
  cpuUsage: {
    userCpuMs: number;
    systemCpuMs: number;
    approxCpuPercent: number;
  };
  memoryUsage: {
    rssMb: number;
    heapUsedMb: number;
    heapTotalMb: number;
  };
  concurrency: {
    throughputReqPerSec: number;
    peakConcurrentRequests: number;
    totalRequestsCompleted: number;
  };
  cacheMetrics: {
    hitRatePercent: number;
    totalHits: number;
    totalMisses: number;
  };
}

export class SystemProfiler {
  private calculatePercentiles(latencies: number[]): { mean: number; p95: number; p99: number } {
    if (latencies.length === 0) return { mean: 0, p95: 0, p99: 0 };
    const sorted = [...latencies].sort((a, b) => a - b);
    const sum = sorted.reduce((acc, v) => acc + v, 0);
    const mean = Math.round((sum / sorted.length) * 100) / 100;
    const p95 = Math.round(sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))] * 100) / 100;
    const p99 = Math.round(sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.99))] * 100) / 100;
    return { mean, p95, p99 };
  }

  /**
   * Profiles the system across all 10 dimensions by exercising message, URL, file, and concurrency workloads.
   */
  async runProfile(options: { iterations?: number; concurrency?: number } = {}): Promise<ProfilerResult> {
    const iterations = options.iterations || 20;
    const concurrency = options.concurrency || 5;

    const startBenchTime = performance.now();
    const initialCpu = process.cpuUsage();
    const apiLatencies: number[] = [];
    const urlLatencies: number[] = [];
    const fileLatencies: number[] = [];

    // Test payloads
    const testMessages = [
      'Your bank account is suspended. Verify credentials at http://fake-login-aba.com immediately!',
      'URGENT: Your parcel delivery is pending unpaid customs fees. Click http://usps-redelivery.info/pay',
      'Congratulations! You won $10,000 lottery award. Telegram @agent_claim now!',
      'Hello, could we reschedule our meeting to tomorrow afternoon? Thanks!',
      'សូមជម្រាបជូនថា គណនីធនាគាររបស់អ្នកត្រូវបានផ្អាក សូមចូលទៅកាន់ http://acleda-update.xyz',
    ];

    const testUrls = [
      'https://paypal.com.verify-account.suspicious-domain.xyz/login',
      'https://google.com',
      'https://secure-aba-banking.com.update-portal.top/auth',
      'https://github.com',
      'http://insecure-phish-portal.icu/signin',
    ];

    // 1. URL Scanning Latency Profiling
    for (const url of testUrls) {
      const t0 = performance.now();
      await urlIntelligence.analyze(url, { skipNetworkProbe: true });
      urlLatencies.push(performance.now() - t0);
    }

    // 2. File Scanning Profiling (Synthetic Buffer via Quarantine)
    const syntheticBuffer = Buffer.from('Normal file buffer content for performance profiling test');
    const { quarantinePath } = quarantineStorage.generateQuarantinePath('txt');
    await fs.promises.writeFile(quarantinePath, syntheticBuffer);
    try {
      for (let i = 0; i < 5; i++) {
        const t0 = performance.now();
        await secureFileAnalyzer.analyze(quarantinePath, `probe-${i}.txt`, 'text/plain', { autoCleanup: false });
        fileLatencies.push(performance.now() - t0);
      }
    } finally {
      await quarantineStorage.secureDelete(quarantinePath);
    }

    // 3. Concurrent Request & Throughput Profiling
    const concurrentBatches = Math.ceil(iterations / concurrency);
    let totalCompleted = 0;

    for (let b = 0; b < concurrentBatches; b++) {
      const batchPromises: Array<Promise<void>> = [];

      for (let c = 0; c < concurrency; c++) {
        const msg = testMessages[(b * concurrency + c) % testMessages.length];
        batchPromises.push(
          (async () => {
            const reqStart = performance.now();
            metricsCollector.incrementActiveRequests();
            try {
              await detectionPipeline.execute({
                type: 'TEXT',
                rawContent: msg,
              });
              apiLatencies.push(performance.now() - reqStart);
              totalCompleted++;
            } finally {
              metricsCollector.decrementActiveRequests();
            }
          })()
        );
      }

      await Promise.all(batchPromises);
    }

    // 4. Repeated Scans for Cache Profiling
    for (let i = 0; i < 5; i++) {
      const reqStart = performance.now();
      await detectionPipeline.execute({
        type: 'TEXT',
        rawContent: testMessages[0],
      });
      apiLatencies.push(performance.now() - reqStart);
      totalCompleted++;
    }

    const elapsedSeconds = Math.max(0.001, (performance.now() - startBenchTime) / 1000);
    const cpuDelta = process.cpuUsage(initialCpu);
    const mem = process.memoryUsage();
    const metrics: PerformanceMetricsReport = metricsCollector.getSummary();

    const apiPerc = this.calculatePercentiles(apiLatencies);
    const urlPerc = this.calculatePercentiles(urlLatencies);
    const filePerc = this.calculatePercentiles(fileLatencies);

    return {
      timestamp: new Date().toISOString(),
      durationSeconds: Math.round(elapsedSeconds * 100) / 100,
      apiResponseTime: {
        meanMs: apiPerc.mean,
        p95Ms: apiPerc.p95,
        p99Ms: apiPerc.p99,
        samples: apiLatencies.length,
      },
      databaseQueries: {
        meanMs: metrics.database.latency_ms.avg,
        p95Ms: metrics.database.latency_ms.p95,
        p99Ms: metrics.database.latency_ms.p99,
        totalQueries: metrics.database.total_queries,
      },
      aiLatency: {
        meanMs: metrics.ai.latency_ms.avg,
        p95Ms: metrics.ai.latency_ms.p95,
        p99Ms: metrics.ai.latency_ms.p99,
        totalCalls: metrics.ai.total_calls,
        cachedCalls: metrics.ai.cached_calls,
        cacheHitRatePercent: metrics.ai.cache_hit_rate_percent,
      },
      externalApi: {
        meanMs: metrics.external_api?.latency_ms?.avg || 0,
        p95Ms: metrics.external_api?.latency_ms?.p95 || 0,
        p99Ms: metrics.external_api?.latency_ms?.p99 || 0,
        totalCalls: metrics.external_api?.total_calls || 0,
      },
      urlScanningTime: {
        meanMs: urlPerc.mean,
        p95Ms: urlPerc.p95,
        p99Ms: urlPerc.p99,
        scansCount: urlLatencies.length,
      },
      fileScanningTime: {
        meanMs: filePerc.mean,
        p95Ms: filePerc.p95,
        p99Ms: filePerc.p99,
        scansCount: fileLatencies.length,
      },
      cpuUsage: {
        userCpuMs: Math.round(cpuDelta.user / 1000),
        systemCpuMs: Math.round(cpuDelta.system / 1000),
        approxCpuPercent: metrics.cpu.approx_cpu_percent,
      },
      memoryUsage: {
        rssMb: Math.round(mem.rss / 1024 / 1024),
        heapUsedMb: Math.round(mem.heapUsed / 1024 / 1024),
        heapTotalMb: Math.round(mem.heapTotal / 1024 / 1024),
      },
      concurrency: {
        throughputReqPerSec: Math.round((totalCompleted / elapsedSeconds) * 10) / 10,
        peakConcurrentRequests: metrics.concurrency?.peak_concurrent_requests || concurrency,
        totalRequestsCompleted: totalCompleted,
      },
      cacheMetrics: {
        hitRatePercent: metrics.cache?.hit_rate_percent || 0,
        totalHits: metrics.cache?.total_hits || 0,
        totalMisses: metrics.cache?.total_misses || 0,
      },
    };
  }
}

export const systemProfiler = new SystemProfiler();
