import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import multer from 'multer';
import { logger } from '../utils/logger';
import { config } from '../config';
import { sendErrorResponse, StandardErrorPayload } from '../utils/responseFormatter';

export type ApiErrorResponse = StandardErrorPayload;

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
): void {
  // Always log internal details and stack trace to Winston structured logs for debugging
  logger.error('Unhandled API Error', {
    event_type: 'API_ERROR',
    method: req.method,
    endpoint: req.originalUrl || req.url,
    error: err.message,
    stack: err.stack,
  });

  // 1. Zod Validation Errors
  if (err instanceof ZodError) {
    const details = err.errors.map((e) => ({
      field: e.path.join('.'),
      message: e.message,
    }));
    sendErrorResponse(
      res,
      400,
      'VALIDATION_ERROR',
      'Request payload validation failed.',
      req,
      details
    );
    return;
  }

  // 2. Multer Upload Errors
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      sendErrorResponse(
        res,
        413,
        'FILE_TOO_LARGE',
        `Uploaded file exceeds the maximum allowed size limit of ${Math.round(config.maxFileSizeBytes / 1024 / 1024)}MB.`,
        req
      );
      return;
    }

    sendErrorResponse(
      res,
      400,
      'UPLOAD_ERROR',
      err.message,
      req
    );
    return;
  }

  // 3. Prisma Database Errors (Prevent DB architecture leakage)
  const errName = err.constructor?.name || '';
  if (errName.includes('Prisma') || (err as any).code?.startsWith?.('P')) {
    const prismaCode = (err as any).code;
    let userMsg = 'A database operation error occurred.';
    let code = 'DATABASE_ERROR';

    if (prismaCode === 'P2002') {
      userMsg = 'A record with these unique credentials already exists.';
      code = 'DUPLICATE_RESOURCE';
    } else if (prismaCode === 'P2025') {
      userMsg = 'The requested resource was not found.';
      code = 'RESOURCE_NOT_FOUND';
    }

    sendErrorResponse(
      res,
      prismaCode === 'P2002' ? 409 : prismaCode === 'P2025' ? 404 : 500,
      code,
      userMsg,
      req
    );
    return;
  }

  // 4. Generic & Unhandled Errors (Never leak raw stack traces or internal filesystem paths to users)
  const statusCode = (err as { status?: number }).status || 500;
  let safeMessage = statusCode === 500
    ? (config.isProduction ? 'An unexpected internal error occurred.' : (err.message || 'Internal Server Error'))
    : (err.message || 'An error occurred during request processing.');

  // Sanitize any accidental filesystem paths or internal details from error messages
  safeMessage = safeMessage
    .replace(/[a-zA-Z]:\\[^ \n\r\t"']+/g, '[internal_path]')
    .replace(/\/(?:[\w.-]+\/)+[\w.-]+/g, '[internal_path]');

  sendErrorResponse(
    res,
    statusCode,
    statusCode === 500 ? 'INTERNAL_SERVER_ERROR' : 'API_ERROR',
    safeMessage,
    req
  );
}
