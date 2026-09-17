import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import prisma from '../database/client';
import { AuthUser } from '../types';
import { hashApiKey } from '../utils/helpers';
import { logger } from '../utils/logger';
import { sendErrorResponse } from '../utils/responseFormatter';
import { tokenRevocationService } from '../services/tokenRevocationService';

export interface AuthenticatedRequest extends Request {
  user?: AuthUser;
}

/**
 * Extracts and verifies JWT token or API Key, attaching user to request if valid.
 * Does not block unauthenticated requests (optional auth).
 */
export async function optionalAuth(req: AuthenticatedRequest, _res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  const apiKeyHeader = req.headers['x-api-key'] as string | undefined;
  const adminKeyHeader = (req.headers['x-admin-key'] || apiKeyHeader) as string | undefined;

  // Master Admin Key support
  if (config.adminApiKey && adminKeyHeader && adminKeyHeader.trim() === config.adminApiKey.trim()) {
    req.user = { id: 'admin-master', email: 'admin@pinit.ai', role: 'admin' };
    return next();
  }

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      if (await tokenRevocationService.isRevoked(token)) {
        return next();
      }
      const decoded = jwt.verify(token, config.jwtSecret) as { id: string; email: string; role: 'user' | 'admin' | 'analyst' };
      req.user = decoded;
      return next();
    } catch {
      // Invalid token, proceed as anonymous
    }
  } else if (apiKeyHeader) {
    try {
      const hashed = hashApiKey(apiKeyHeader);
      const user = await prisma.user.findUnique({
        where: { apiKeyHash: hashed },
        select: { id: true, email: true, role: true },
      });
      if (user) {
        req.user = user as AuthUser;
        return next();
      }
    } catch {
      // Proceed as anonymous
    }
  }

  next();
}

/**
 * Requires valid authentication (JWT or API Key).
 */
export async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
  await optionalAuth(req, res, () => {
    if (!req.user) {
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
      const clientIpHash = require('crypto').createHash('sha256').update(`pinit_ip_salt:${clientIp}`).digest('hex');
      const reason = req.headers.authorization
        ? 'Invalid or expired token'
        : (req.headers['x-api-key'] ? 'Invalid API key' : 'Missing credentials');

      logger.trackAuthFailure({
        reason,
        endpoint: req.originalUrl || req.url,
        clientIpHash,
      });

      sendErrorResponse(
        res,
        401,
        'UNAUTHORIZED',
        'Authentication required. Provide a valid Bearer token or X-API-Key header.',
        req
      );
      return;
    }
    next();
  });
}

/**
 * Explicit hierarchical role permissions.
 * Admins inherit all privileges of analysts and users.
 */
export const ROLE_HIERARCHY: Record<string, number> = {
  admin: 3,
  analyst: 2,
  user: 1,
};

/**
 * Requires minimum role level in the role hierarchy (e.g. 'analyst' allows analyst and admin).
 */
export function requireRole(requiredRole: 'admin' | 'analyst' | 'user') {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const userRole = req.user?.role || 'user';
    const userWeight = ROLE_HIERARCHY[userRole] ?? 0;
    const requiredWeight = ROLE_HIERARCHY[requiredRole] ?? 0;

    if (!req.user || userWeight < requiredWeight) {
      sendErrorResponse(
        res,
        403,
        'FORBIDDEN',
        `Insufficient permissions. Requires '${requiredRole}' role or higher.`,
        req
      );
      return;
    }
    next();
  };
}
