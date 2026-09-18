import { Request, Response, NextFunction } from 'express';
import net from 'net';
import fs from 'fs';
import prisma from '../database/client';
import { config } from '../config';
import { metricsCollector } from '../modules/monitoring/metricsCollector';

// ---------------------------------------------------------------------------
// Statistics cache — avoids running 9 DB count queries on every request
// ---------------------------------------------------------------------------
interface StatsCache {
  data: Record<string, any>;
  cachedAt: number;
}
const STATS_CACHE_TTL_MS = 30_000; // 30 seconds
let statsCache: StatsCache | null = null;

export class SystemController {
  /**
   * GET /api/health (also /health and /api/v1/health)
   * General platform health, uptime, and high-level service status.
   */
  async getHealth(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // 1. Database Check
      let dbHealthy = false;
      let dbLatencyMs = 0;
      try {
        const start = Date.now();
        await prisma.$queryRaw`SELECT 1`;
        dbLatencyMs = Date.now() - start;
        metricsCollector.recordDbQuery(dbLatencyMs);
        dbHealthy = true;
      } catch {
        dbHealthy = false;
      }

      // 2. ClamAV Probe
      const clamavHealthy = await checkTcpPort(config.clamav.host, config.clamav.port, 1000);

      const isHealthy = dbHealthy;
      const statusCode = isHealthy ? 200 : 503;

      res.status(statusCode).json({
        status: isHealthy ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        uptime_seconds: Math.floor(process.uptime()),
        services: {
          database: dbHealthy ? 'connected' : 'disconnected',
          database_latency_ms: dbLatencyMs,
          clamav_antivirus: clamavHealthy ? 'online' : 'offline_fallback_active',
          queue: config.redisUrl ? 'redis_bullmq' : 'in_process_async',
        },
        memory: {
          rss_mb: Math.round(process.memoryUsage().rss / 1024 / 1024),
          heap_used_mb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        },
        version: '1.0.0',
        environment: config.nodeEnv,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/health/database (also /health/database)
   * Detailed health check endpoint for the database subsystem.
   */
  async getDatabaseHealth(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const start = Date.now();
      let connected = false;
      let errorMsg: string | null = null;
      let activeScansCount = 0;

      try {
        await prisma.$queryRaw`SELECT 1`;
        connected = true;
        activeScansCount = await prisma.scan.count();
      } catch (err) {
        connected = false;
        errorMsg = (err as Error).message;
      }

      const latencyMs = Date.now() - start;
      metricsCollector.recordDbQuery(latencyMs);
      const statusCode = connected ? 200 : 503;

      res.status(statusCode).json({
        status: connected ? 'healthy' : 'unhealthy',
        database: {
          status: connected ? 'connected' : 'disconnected',
          latency_ms: latencyMs,
          provider: 'sqlite',
          total_records: activeScansCount,
          error: errorMsg,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/health/services (also /health/services)
   * Comprehensive health check evaluating all supporting backend subsystems.
   */
  async getServicesHealth(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // 1. Database Probe
      const dbStart = Date.now();
      let dbConnected = false;
      try {
        await prisma.$queryRaw`SELECT 1`;
        dbConnected = true;
      } catch {
        dbConnected = false;
      }
      const dbLatencyMs = Date.now() - dbStart;
      metricsCollector.recordDbQuery(dbLatencyMs);

      // 2. ClamAV Antivirus TCP Probe
      const clamavOnline = await checkTcpPort(config.clamav.host, config.clamav.port, 1000);

      // 3. Storage / Quarantine Directory Accessibility
      let storageAccessible = false;
      try {
        if (!fs.existsSync(config.uploadTempDir)) {
          fs.mkdirSync(config.uploadTempDir, { recursive: true });
        }
        fs.accessSync(config.uploadTempDir, fs.constants.R_OK | fs.constants.W_OK);
        storageAccessible = true;
      } catch {
        storageAccessible = false;
      }

      const isOverallHealthy = dbConnected && storageAccessible;
      const statusCode = isOverallHealthy ? 200 : 503;

      res.status(statusCode).json({
        status: isOverallHealthy ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        uptime_seconds: Math.floor(process.uptime()),
        services: {
          database: {
            status: dbConnected ? 'connected' : 'disconnected',
            latency_ms: dbLatencyMs,
          },
          clamav_antivirus: {
            status: clamavOnline ? 'online' : 'offline_fallback_active',
            host: config.clamav.host,
            port: config.clamav.port,
            fallback: 'built_in_static_signatures',
          },
          task_queue: {
            status: 'operational',
            mode: config.redisUrl ? 'redis_bullmq' : 'in_memory_async',
          },
          ai_explanation_engine: {
            status: config.geminiApiKey ? 'gemini_configured' : 'rules_engine_fallback_active',
            model: config.geminiModel,
            circuit_breaker: 'enabled',
          },
          threat_intelligence: {
            status: config.virusTotalApiKey ? 'virustotal_configured' : 'heuristic_fallback_active',
          },
          storage_quarantine: {
            status: storageAccessible ? 'accessible' : 'inaccessible',
            path: config.uploadTempDir,
          },
        },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/statistics
   * Global threat and scan metrics.
   */
  async getStatistics(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const now = Date.now();

      // Return cached result if still fresh (avoids 9 DB queries on every poll)
      if (statsCache && now - statsCache.cachedAt < STATS_CACHE_TTL_MS) {
        res.status(200).json({
          success: true,
          statistics: statsCache.data,
          data: statsCache.data,
          cached: true,
          cache_age_ms: now - statsCache.cachedAt,
        });
        return;
      }

      const dbStart = Date.now();
      const [
        totalScans,
        fileScans,
        urlScans,
        completedScans,
        maliciousScans,
        highRiskScans,
        suspiciousScans,
        safeScans,
        totalDetections,
      ] = await Promise.all([
        prisma.scan.count(),
        prisma.scan.count({ where: { type: 'FILE' } }),
        prisma.scan.count({ where: { type: 'URL' } }),
        prisma.scan.count({ where: { status: 'COMPLETED' } }),
        prisma.scan.count({ where: { riskLevel: 'MALICIOUS' } }),
        prisma.scan.count({ where: { riskLevel: 'HIGH_RISK' } }),
        prisma.scan.count({ where: { riskLevel: 'SUSPICIOUS' } }),
        prisma.scan.count({ where: { riskLevel: 'SAFE' } }),
        prisma.detection.count(),
      ]);
      metricsCollector.recordDbQuery(Date.now() - dbStart);

      const statsPayload = {
        total_scans: totalScans,
        completed_scans: completedScans,
        by_type: {
          file: fileScans,
          files: fileScans,
          url: urlScans,
          urls: urlScans,
        },
        by_risk_level: {
          malicious: maliciousScans,
          high_risk: highRiskScans,
          suspicious: suspiciousScans,
          safe: safeScans,
        },
        by_threat_level: {
          malicious: maliciousScans,
          high_risk: highRiskScans,
          suspicious: suspiciousScans,
          safe: safeScans,
        },
        total_detections_logged: totalDetections,
        last_updated: new Date().toISOString(),
      };

      // Update in-process cache
      statsCache = { data: statsPayload, cachedAt: Date.now() };

      res.status(200).json({
        success: true,
        statistics: statsPayload,
        data: statsPayload,
      });
    } catch (err) {
      next(err);
    }
  }

  async getPerformanceMetrics(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.setHeader('Cache-Control', 'public, max-age=2, stale-while-revalidate=5');
      const summary = metricsCollector.getSummary();
      const performanceMetrics = {
        api_response_time: {
          ...summary.api.latency_ms,
          p50_ms: summary.api.latency_ms.p50,
          p95_ms: summary.api.latency_ms.p95,
          p99_ms: summary.api.latency_ms.p99,
          avg_ms: summary.api.latency_ms.avg,
          min_ms: summary.api.latency_ms.min,
          max_ms: summary.api.latency_ms.max,
          total_requests: summary.api.total_requests,
          slow_requests: summary.api.slow_requests,
          error_requests: summary.api.error_requests,
        },
        ai_latency: summary.ai,
        database_queries: summary.database,
        url_analysis: summary.url_analysis,
        file_processing: summary.file_processing,
        external_api: summary.external_api,
        external_api_latency: summary.external_api,
        concurrency: summary.concurrency,
        concurrent_requests: summary.concurrency,
        cache: summary.cache,
        cache_hit_rate: summary.cache,
        memory: summary.memory,
        cpu: summary.cpu,
        scans: summary.scans,
        feedback: summary.feedback,
        queue: summary.queue,
        alerts: metricsCollector.evaluateThresholdAlerts(),
        error_rate_pct: summary.api.error_rate_percent,
        timeout_rate_pct: summary.api.timeout_rate_percent,
      };

      res.status(200).json({
        success: true,
        timestamp: summary.timestamp,
        uptime_seconds: summary.uptime_seconds,
        performance_metrics: performanceMetrics,
        metrics: {
          ...summary,
          api_response_time: performanceMetrics.api_response_time,
          ai_latency: performanceMetrics.ai_latency,
          database_queries: performanceMetrics.database_queries,
          external_api_latency: performanceMetrics.external_api,
          concurrent_requests: performanceMetrics.concurrency,
          cache_hit_rate: performanceMetrics.cache,
          scans: summary.scans,
          feedback: summary.feedback,
          queue: summary.queue,
          alerts: performanceMetrics.alerts,
        },
        data: performanceMetrics,
      });
    } catch (err) {
      next(err);
    }
  }
}

/**
 * Utility to test TCP port connection quickly
 */
function checkTcpPort(host: string, port: number, timeoutMs = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);

    socket.connect(port, host, () => {
      socket.destroy();
      resolve(true);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  });
}

export const systemController = new SystemController();
