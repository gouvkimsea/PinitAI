import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

export interface RequestWithId extends Request {
  id?: string;
  requestId?: string;
}

/**
 * Middleware that assigns a unique tracing request_id to every incoming HTTP request.
 * If client provides an existing X-Request-Id header, that ID is preserved.
 */
export function requestIdMiddleware(req: RequestWithId, res: Response, next: NextFunction): void {
  const incomingId = req.headers['x-request-id'];
  const requestId = typeof incomingId === 'string' && incomingId.trim().length > 0
    ? incomingId.trim()
    : uuidv4();

  req.id = requestId;
  req.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);

  next();
}

/**
 * Helper to safely extract request ID from request or generate fallback
 */
export function getRequestId(req?: Request): string {
  if (!req) return uuidv4();
  const reqWithId = req as RequestWithId;
  return reqWithId.id || reqWithId.requestId || (typeof req.headers?.['x-request-id'] === 'string' ? req.headers['x-request-id'] : uuidv4());
}
