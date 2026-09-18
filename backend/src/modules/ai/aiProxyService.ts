import { config } from '../../config';
import { logger } from '../../utils/logger';
import { metricsCollector } from '../monitoring/metricsCollector';
import { aiCircuitBreaker } from './circuitBreaker';

/**
 * Creates an AbortController that fires after `timeoutMs` milliseconds.
 * Returns the controller and a cleanup function to prevent timer leaks.
 */
function createTimeoutController(timeoutMs: number): { controller: AbortController; clear: () => void } {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  return { controller, clear: () => clearTimeout(id) };
}

/**
 * Helper to build headers for administrative endpoints
 */
function getAdminHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  if (config.adminApiKey) {
    headers['X-Admin-Key'] = config.adminApiKey;
  }
  return headers;
}

/**
 * Shared fetch wrapper with timeout, circuit breaker protection, latency recording, and structured error logging.
 */
async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = config.timeouts.aiRequestTimeoutMs,
  label = 'AI Engine'
): Promise<Response> {
  // Fail fast if circuit breaker is OPEN to avoid saturating concurrency slots
  if (aiCircuitBreaker.isOpen()) {
    const errorMsg = `Circuit breaker is OPEN for ${label}; bypassing call to protect worker pool`;
    logger.warn(errorMsg, { url, state: aiCircuitBreaker.getState() });
    throw new Error(errorMsg);
  }

  const { controller, clear } = createTimeoutController(timeoutMs);
  const startTime = Date.now();

  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    metricsCollector.recordAiCall(Date.now() - startTime, false);
    if (res.ok) {
      aiCircuitBreaker.recordSuccess();
    } else if (res.status >= 500) {
      aiCircuitBreaker.recordFailure(`HTTP ${res.status}`);
    }
    return res;
  } catch (err) {
    aiCircuitBreaker.recordFailure((err as Error).message);
    metricsCollector.recordAiCall(Date.now() - startTime, false, true);
    const isTimeout = (err as Error).name === 'AbortError';
    logger.warn(`${label} request ${isTimeout ? 'timed out' : 'failed'}`, {
      url,
      timeoutMs,
      error: (err as Error).message,
    });
    throw err;
  } finally {
    clear();
  }
}

import crypto from 'crypto';
import { LruCache } from '../../utils/lruCache';

export class AiProxyService {
  private messageCache = new LruCache<string, any>({ maxSize: 1000, defaultTtlMs: 15 * 60 * 1000 });
  private urlCache = new LruCache<string, any>({ maxSize: 1000, defaultTtlMs: 15 * 60 * 1000 });

  private get aiBase(): string {
    return config.aiEngineUrl.replace(/\/+$/, '');
  }

  /**
   * Forwards message to Python AI Engine with in-memory LRU response caching
   */
  async analyzeMessage(content: string): Promise<any> {
    const cacheKey = crypto.createHash('sha256').update(content.trim()).digest('hex');
    const cached = this.messageCache.get(cacheKey);
    if (cached) {
      metricsCollector.recordAiCall(0, true);
      metricsCollector.recordCacheLookup(true);
      return cached;
    }

    metricsCollector.recordCacheLookup(false);

    const res = await fetchWithTimeout(
      `${this.aiBase}/api/analyze/message`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
      },
      config.timeouts.aiRequestTimeoutMs,
      'AI Engine /analyze/message'
    );

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error((errData as any).detail || `AI Engine returned HTTP ${res.status}`);
    }

    const data = await res.json();
    this.messageCache.set(cacheKey, data);
    return data;
  }

  /**
   * Forwards URL to Python AI Engine with in-memory LRU response caching
   */
  async analyzeUrl(url: string): Promise<any> {
    const cacheKey = crypto.createHash('sha256').update(url.trim().toLowerCase()).digest('hex');
    const cached = this.urlCache.get(cacheKey);
    if (cached) {
      metricsCollector.recordAiCall(0, true);
      metricsCollector.recordCacheLookup(true);
      return cached;
    }

    metricsCollector.recordCacheLookup(false);

    const res = await fetchWithTimeout(
      `${this.aiBase}/api/analyze/url`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      },
      config.timeouts.aiRequestTimeoutMs,
      'AI Engine /analyze/url'
    );

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error((errData as any).detail || `AI Engine returned HTTP ${res.status}`);
    }

    const data = await res.json();
    this.urlCache.set(cacheKey, data);
    return data;
  }

  /**
   * Forwards QR payload or image FormData to Python AI Engine
   */
  async analyzeQr(formData: FormData): Promise<any> {
    const res = await fetchWithTimeout(
      `${this.aiBase}/api/analyze/qr`,
      { method: 'POST', body: formData },
      config.timeouts.aiRequestTimeoutMs,
      'AI Engine /analyze/qr'
    );

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error((errData as any).detail || `AI Engine returned HTTP ${res.status}`);
    }

    return await res.json();
  }

  /**
   * Requests 5-point explanation from Python AI Engine
   */
  async explainEvidence(payload: any): Promise<any> {
    const res = await fetchWithTimeout(
      `${this.aiBase}/api/explain`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      },
      config.timeouts.aiRequestTimeoutMs,
      'AI Engine /explain'
    );

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error((errData as any).detail || `AI Engine returned HTTP ${res.status}`);
    }

    return await res.json();
  }

  /**
   * Forwards user accuracy feedback to Python AI Engine
   */
  async forwardFeedback(feedback: {
    scan_id: string;
    is_correct: boolean;
    suggested_category?: string;
    comments?: string;
  }): Promise<any> {
    try {
      const res = await fetchWithTimeout(
        `${this.aiBase}/api/feedback`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(feedback),
        },
        config.timeouts.aiRequestTimeoutMs,
        'AI Engine /feedback'
      );
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      logger.warn('Failed to forward feedback to Python AI Engine', { error: (err as Error).message });
    }
    return { success: true, message: 'Feedback recorded locally.' };
  }

  /**
   * Retrieves telemetry metrics from AI Engine — graceful fallback on failure.
   */
  async getAdminStats(): Promise<any> {
    try {
      const res = await fetchWithTimeout(
        `${this.aiBase}/api/admin/stats`,
        { headers: getAdminHeaders() },
        config.timeouts.aiRequestTimeoutMs,
        'AI Engine /admin/stats'
      );
      if (!res.ok) {
        logger.warn('AI Engine admin/stats returned non-OK status', { status: res.status });
        return null;
      }
      return await res.json();
    } catch (err) {
      logger.warn('AI Engine admin/stats unavailable', { error: (err as Error).message });
      return null;
    }
  }

  async getAdminMetrics(): Promise<any> {
    try {
      const res = await fetchWithTimeout(
        `${this.aiBase}/api/admin/metrics`,
        { headers: getAdminHeaders() },
        config.timeouts.aiRequestTimeoutMs,
        'AI Engine /admin/metrics'
      );
      if (!res.ok) {
        logger.warn('AI Engine admin/metrics returned non-OK status', { status: res.status });
        return null;
      }
      return await res.json();
    } catch (err) {
      logger.warn('AI Engine admin/metrics unavailable', { error: (err as Error).message });
      return null;
    }
  }

  async getAdminDataset(): Promise<any> {
    try {
      const res = await fetchWithTimeout(
        `${this.aiBase}/api/admin/dataset`,
        { headers: getAdminHeaders() },
        config.timeouts.aiRequestTimeoutMs,
        'AI Engine /admin/dataset'
      );
      if (!res.ok) {
        logger.warn('AI Engine admin/dataset returned non-OK status', { status: res.status });
        return null;
      }
      return await res.json();
    } catch (err) {
      logger.warn('AI Engine admin/dataset unavailable', { error: (err as Error).message });
      return null;
    }
  }

  async verifyDatasetItem(id: string): Promise<any> {
    const res = await fetchWithTimeout(
      `${this.aiBase}/api/admin/dataset/verify/${id}`,
      {
        method: 'POST',
        headers: getAdminHeaders(),
      },
      config.timeouts.aiRequestTimeoutMs,
      'AI Engine /admin/dataset/verify'
    );
    return await res.json();
  }
}

export const aiProxyService = new AiProxyService();
