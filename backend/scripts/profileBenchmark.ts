// Configure generous rate limits for profiling benchmark so benchmark measures pure server throughput
process.env.RATE_LIMIT_TEXT_MAX = '500';
process.env.RATE_LIMIT_URL_MAX = '500';
process.env.RATE_LIMIT_MAX_REQUESTS = '1000';

import request from 'supertest';
import { createApp } from '../src/app';
import prisma from '../src/database/client';
import { metricsCollector } from '../src/modules/monitoring/metricsCollector';

interface BenchmarkRunResult {
  totalRequests: number;
  concurrency: number;
  durationMs: number;
  throughputReqPerSec: number;
  latencies: {
    avg: number;
    p50: number;
    p95: number;
    p99: number;
    min: number;
    max: number;
  };
  databaseQueries: {
    count: number;
    avgLatencyMs: number;
  };
  externalApiCalls: {
    count: number;
    avgLatencyMs: number;
  };
  aiRequests: {
    count: number;
    avgLatencyMs: number;
  };
  memory: {
    rssMb: number;
    heapUsedMb: number;
    heapTotalMb: number;
  };
  cacheHitRatePercent: number;
}

function calculatePercentiles(latencies: number[]) {
  if (latencies.length === 0) {
    return { avg: 0, p50: 0, p95: 0, p99: 0, min: 0, max: 0 };
  }
  const sorted = [...latencies].sort((a, b) => a - b);
  const count = sorted.length;
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  return {
    avg: Math.round((sum / count) * 100) / 100,
    p50: sorted[Math.floor(count * 0.5)],
    p95: sorted[Math.min(count - 1, Math.floor(count * 0.95))],
    p99: sorted[Math.min(count - 1, Math.floor(count * 0.99))],
    min: sorted[0],
    max: sorted[count - 1],
  };
}

export async function runProfileBenchmark(label: string, totalRequests = 100, concurrency = 10): Promise<BenchmarkRunResult> {
  const app = createApp();

  // Test payloads covering URL scan, message/text scan, duplicate targets, and cache lookups
  const samplePayloads = [
    { type: 'text', payload: { content: 'Congratulations! You won 1,000,000 USD! Click http://claim-prize-bank-now.com to claim immediately.' } },
    { type: 'url', payload: { url: 'https://google.com/search?q=security' } },
    { type: 'text', payload: { content: 'Hello mom, I lost my phone, please transfer $50 to my friend Bakong account.' } },
    { type: 'url', payload: { url: 'http://phishing-test-login.com/auth' } },
    { type: 'text', payload: { content: 'Dear user, your package delivery is pending verification at http://track-parcel-express.xyz/login' } },
    { type: 'text', payload: { content: 'Can we meet tomorrow at 10 AM for coffee?' } }, // benign text
    { type: 'url', payload: { url: 'https://en.wikipedia.org/wiki/Computer_security' } }, // benign URL
  ];

  metricsCollector.reset();
  const startDbCount = metricsCollector.getSummary().database.total_queries;
  const startExtCount = metricsCollector.getSummary().external_api.total_calls;
  const startAiCount = metricsCollector.getSummary().ai.total_calls;

  const latencies: number[] = [];
  const startOverall = Date.now();

  // Run in concurrent worker batches
  let index = 0;
  const worker = async () => {
    while (true) {
      const current = index++;
      if (current >= totalRequests) break;

      const sample = samplePayloads[current % samplePayloads.length];
      const reqStart = Date.now();

      if (sample.type === 'url') {
        await request(app)
          .post('/api/analyze/url')
          .send(sample.payload)
          .set('Accept', 'application/json');
      } else {
        await request(app)
          .post('/api/analyze/text')
          .send(sample.payload)
          .set('Accept', 'application/json');
      }

      const dur = Date.now() - reqStart;
      latencies.push(dur);
    }
  };

  const workers: Promise<void>[] = [];
  for (let i = 0; i < concurrency; i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  const durationMs = Date.now() - startOverall;
  const summary = metricsCollector.getSummary();
  const stats = calculatePercentiles(latencies);
  const throughput = Math.round((totalRequests / (durationMs / 1000)) * 100) / 100;

  const result: BenchmarkRunResult = {
    totalRequests,
    concurrency,
    durationMs,
    throughputReqPerSec: throughput,
    latencies: stats,
    databaseQueries: {
      count: summary.database.total_queries - startDbCount,
      avgLatencyMs: summary.database.latency_ms.avg,
    },
    externalApiCalls: {
      count: summary.external_api.total_calls - startExtCount,
      avgLatencyMs: summary.external_api.latency_ms.avg,
    },
    aiRequests: {
      count: summary.ai.total_calls - startAiCount,
      avgLatencyMs: summary.ai.latency_ms.avg,
    },
    memory: {
      rssMb: summary.memory.rss_mb,
      heapUsedMb: summary.memory.heap_used_mb,
      heapTotalMb: summary.memory.heap_total_mb,
    },
    cacheHitRatePercent: summary.cache.hit_rate_percent,
  };

  console.log(`\n================== BENCHMARK PROFILE: ${label} ==================`);
  console.log(`Requests: ${result.totalRequests} | Concurrency: ${result.concurrency} | Total Time: ${result.durationMs}ms`);
  console.log(`Throughput: ${result.throughputReqPerSec} req/sec`);
  console.log(`Latency: Avg ${result.latencies.avg}ms | p50 ${result.latencies.p50}ms | p95 ${result.latencies.p95}ms | p99 ${result.latencies.p99}ms (Min: ${result.latencies.min}ms, Max: ${result.latencies.max}ms)`);
  console.log(`DB Queries: ${result.databaseQueries.count} (Avg: ${result.databaseQueries.avgLatencyMs}ms)`);
  console.log(`External API calls: ${result.externalApiCalls.count} (Avg: ${result.externalApiCalls.avgLatencyMs}ms)`);
  console.log(`AI Calls: ${result.aiRequests.count} (Avg: ${result.aiRequests.avgLatencyMs}ms)`);
  console.log(`Memory: RSS ${result.memory.rssMb}MB | Heap Used ${result.memory.heapUsedMb}MB | Heap Total ${result.memory.heapTotalMb}MB`);
  console.log(`Cache Hit Rate: ${result.cacheHitRatePercent}%`);
  console.log(`=================================================================\n`);

  return result;
}

if (require.main === module || process.env.RUN_STANDALONE_BENCHMARK) {
  runProfileBenchmark('Baseline Profile', 80, 8)
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
