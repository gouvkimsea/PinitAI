import { Request, Response, NextFunction } from 'express';
import { config } from '../config';
import { logger } from '../utils/logger';
import { sendErrorResponse } from '../utils/responseFormatter';
import { metricsCollector } from '../modules/monitoring/metricsCollector';

/**
 * Request timeout middleware.
 * Aborts hanging requests after the configured timeout (default: 30 seconds).
 */
export function requestTimeoutMiddleware(timeoutMs: number = config.timeouts.requestTimeoutMs) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        metricsCollector.recordTimeout();
        logger.warn(`Request timed out after ${timeoutMs}ms`, {
          method: req.method,
          path: req.originalUrl,
          ip: req.ip,
        });

        sendErrorResponse(
          res,
          504,
          'GATEWAY_TIMEOUT',
          `Request processing exceeded timeout limit of ${timeoutMs}ms. Please retry or reduce payload complexity.`,
          req
        );
      }
    }, timeoutMs);

    // Clear the timeout when the response completes
    res.on('finish', () => clearTimeout(timer));
    res.on('close', () => clearTimeout(timer));

    next();
  };
}
