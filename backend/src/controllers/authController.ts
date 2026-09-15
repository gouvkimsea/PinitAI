import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import prisma from '../database/client';
import { config } from '../config';
import { generateApiKey, hashApiKey } from '../utils/helpers';
import { AuthenticatedRequest } from '../middleware/auth';
import { logSecurityEvent } from '../utils/securityEventLogger';
import { logger } from '../utils/logger';
import { sendErrorResponse } from '../utils/responseFormatter';
import { tokenRevocationService } from '../services/tokenRevocationService';
import { flushAuditLogsNow } from '../middleware/auditLogger';

const RegisterSchema = z.object({
  email: z.string().email('Invalid email address format.'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters long.')
    .max(128, 'Password cannot exceed 128 characters.')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter.')
    .regex(/[0-9]/, 'Password must contain at least one number.'),
});

const LoginSchema = z.object({
  email: z.string().email('Invalid email address format.'),
  password: z.string().min(1, 'Password is required.'),
});

const ForgotPasswordSchema = z.object({
  email: z.string().email('Invalid email address format.'),
});

const ResetPasswordSchema = z.object({
  token: z.string().min(10, 'Valid reset token is required.'),
  newPassword: z
    .string()
    .min(8, 'Password must be at least 8 characters long.')
    .max(128, 'Password cannot exceed 128 characters.')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter.')
    .regex(/[0-9]/, 'Password must contain at least one number.'),
});

export class AuthController {
  /**
   * POST /api/v1/auth/register
   * Registers a new user and issues an API key + JWT token.
   */
  async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email, password } = RegisterSchema.parse(req.body);

      const existing = await prisma.user.findUnique({
        where: { email: email.toLowerCase() },
      });

      if (existing) {
        sendErrorResponse(
          res,
          409,
          'USER_ALREADY_EXISTS',
          'A user with this email address is already registered.',
          req
        );
        return;
      }

      const passwordHash = await bcrypt.hash(password, 12);
      const rawApiKey = generateApiKey();
      const apiKeyHash = hashApiKey(rawApiKey);

      const user = await prisma.user.create({
        data: {
          email: email.toLowerCase(),
          passwordHash,
          apiKeyHash,
          role: 'user',
        },
      });

      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role, jti: crypto.randomUUID() },
        config.jwtSecret,
        { expiresIn: config.jwtExpiresIn } as jwt.SignOptions
      );

      res.status(201).json({
        success: true,
        message: 'User successfully registered.',
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          api_key: rawApiKey,
        },
        token,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/auth/login
   * Authenticates user and returns JWT token.
   */
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email, password } = LoginSchema.parse(req.body);

      const user = await prisma.user.findUnique({
        where: { email: email.toLowerCase() },
      });

      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
      const clientIpHash = crypto.createHash('sha256').update(`pinit_ip_salt:${clientIp}`).digest('hex');

      if (!user) {
        logger.trackAuthFailure({
          reason: 'User account not found',
          endpoint: req.originalUrl || '/api/auth/login',
          clientIpHash,
        });

        sendErrorResponse(
          res,
          401,
          'INVALID_CREDENTIALS',
          'Invalid email or password provided.',
          req
        );
        return;
      }

      const isMatch = await bcrypt.compare(password, user.passwordHash);
      if (!isMatch) {
        logger.trackAuthFailure({
          reason: 'Incorrect password',
          endpoint: req.originalUrl || '/api/auth/login',
          clientIpHash,
          userId: user.id,
        });

        logSecurityEvent({
          eventType: 'AUTH_FAILURE',
          severity: 'WARNING',
          userId: user.id,
          rawIp: req.ip || req.socket.remoteAddress,
          targetResource: '/api/v1/auth/login',
          details: { email: email.toLowerCase(), reason: 'invalid_password' },
        }).catch(() => {});

        sendErrorResponse(
          res,
          401,
          'INVALID_CREDENTIALS',
          'Invalid email or password provided.',
          req
        );
        return;
      }

      // Update user lastLoginAt timestamp
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      }).catch(() => {});

      logSecurityEvent({
        eventType: 'AUTH_SUCCESS',
        severity: 'INFO',
        userId: user.id,
        rawIp: req.ip || req.socket.remoteAddress,
        targetResource: '/api/v1/auth/login',
      }).catch(() => {});

      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role, jti: crypto.randomUUID() },
        config.jwtSecret,
        { expiresIn: config.jwtExpiresIn } as jwt.SignOptions
      );

      res.status(200).json({
        success: true,
        message: 'Authentication successful.',
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          api_key: user.apiKeyHash ? 'pk_****************' : null,
        },
        token,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/auth/me
   * Returns authenticated user profile.
   */
  async getProfile(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        sendErrorResponse(res, 401, 'UNAUTHORIZED', 'Not authenticated.', req);
        return;
      }

      const user = await prisma.user.findUnique({
        where: { id: req.user.id },
        select: { id: true, email: true, role: true, apiKeyHash: true, createdAt: true },
      });

      if (!user) {
        sendErrorResponse(res, 404, 'USER_NOT_FOUND', 'User record not found.', req);
        return;
      }

      res.status(200).json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          api_key: user.apiKeyHash ? 'pk_****************' : null,
          created_at: user.createdAt,
        },
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/auth/api-key/regenerate
   * Generates a new API key for the authenticated user and returns the plaintext key once.
   */
  async regenerateApiKey(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        sendErrorResponse(res, 401, 'UNAUTHORIZED', 'Not authenticated.', req);
        return;
      }

      const rawApiKey = generateApiKey();
      const apiKeyHash = hashApiKey(rawApiKey);

      await prisma.user.update({
        where: { id: req.user.id },
        data: { apiKeyHash },
      });

      res.status(200).json({
        success: true,
        message: 'New API key generated successfully. Save it immediately; it will not be shown again.',
        api_key: rawApiKey,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/auth/logout
   * Immediately revokes the current JWT bearer token.
   */
  async logout(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        await tokenRevocationService.revokeToken(token);
      }

      res.status(200).json({
        success: true,
        message: 'Successfully logged out. Session token has been revoked.',
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/auth/refresh
   * Exchanges an active valid JWT for a fresh short-lived session token.
   */
  async refresh(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        sendErrorResponse(res, 401, 'UNAUTHORIZED', 'Valid active session required to refresh token.', req);
        return;
      }

      const user = await prisma.user.findUnique({
        where: { id: req.user.id },
      });

      if (!user || user.status !== 'active') {
        sendErrorResponse(res, 403, 'FORBIDDEN', 'User account is inactive or disabled.', req);
        return;
      }

      const newToken = jwt.sign(
        { id: user.id, email: user.email, role: user.role, jti: crypto.randomUUID() },
        config.jwtSecret,
        { expiresIn: config.jwtExpiresIn } as jwt.SignOptions
      );

      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully.',
        token: newToken,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * DELETE /api/v1/auth/me
   * Permanently deletes user account, invalidates active sessions, and wipes personal credentials (GDPR Right to Erasure).
   * Requires current password verification for security.
   */
  async deleteAccount(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        sendErrorResponse(res, 401, 'UNAUTHORIZED', 'Authentication is required to delete account.', req);
        return;
      }

      const { password } = req.body || {};
      if (!password || typeof password !== 'string') {
        sendErrorResponse(res, 400, 'PASSWORD_REQUIRED', 'Current password is required to confirm account deletion.', req);
        return;
      }

      const user = await prisma.user.findUnique({
        where: { id: req.user.id },
      });

      if (!user) {
        sendErrorResponse(res, 404, 'USER_NOT_FOUND', 'User record not found.', req);
        return;
      }

      const passwordValid = await bcrypt.compare(password, user.passwordHash);
      if (!passwordValid) {
        logSecurityEvent({
          userId: user.id,
          eventType: 'AUTH_FAILURE',
          severity: 'WARNING',
          targetResource: '/api/v1/auth/me',
          details: { reason: 'Incorrect password during account deletion attempt' },
          rawIp: req.ip || req.socket?.remoteAddress,
        });

        sendErrorResponse(res, 401, 'INVALID_CREDENTIALS', 'Incorrect password. Account deletion aborted.', req);
        return;
      }

      // Revoke the active token if present
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        await tokenRevocationService.revokeToken(token);
      }

      logSecurityEvent({
        userId: user.id,
        eventType: 'USER_DELETED',
        severity: 'INFO',
        targetResource: '/api/v1/auth/me',
        details: { email: user.email, action: 'GDPR Right to Erasure' },
        rawIp: req.ip || req.socket?.remoteAddress,
      });

      // Flush any queued audit records while the user is still active to avoid FK race
      await flushAuditLogsNow();

      // Delete the user record
      await prisma.user.delete({
        where: { id: user.id },
      });

      logger.info('User account permanently deleted', { userId: user.id, email: user.email });

      res.status(200).json({
        success: true,
        message: 'Account and associated personal records have been permanently deleted.',
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/auth/forgot-password
   * Issues a short-lived cryptographic reset token tied to the user's current password hash.
   * Defends against account enumeration by always returning 200 OK.
   */
  async forgotPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email } = ForgotPasswordSchema.parse(req.body);
      const user = await prisma.user.findUnique({
        where: { email: email.toLowerCase() },
      });

      let resetToken: string | undefined;

      if (user && user.status === 'active') {
        // Sign token with secret derived from current passwordHash
        resetToken = jwt.sign(
          { id: user.id, email: user.email, type: 'pwd_reset' },
          config.jwtSecret + user.passwordHash,
          { expiresIn: '15m' }
        );

        logger.info('Password reset token generated', { userId: user.id });
      }

      // In non-production environments (test/dev), return token in body for automated testing
      const isTestEnv = config.nodeEnv === 'test' || config.nodeEnv === 'development';

      res.status(200).json({
        success: true,
        message: 'If the provided email address is registered, password reset instructions have been dispatched.',
        ...(isTestEnv && resetToken ? { reset_token: resetToken } : {}),
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/auth/reset-password
   * Verifies the cryptographic reset token and updates the user's password.
   * Immediately invalidates the reset token because the password hash changes.
   */
  async resetPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { token, newPassword } = ResetPasswordSchema.parse(req.body);

      // Decode payload without verification first to extract user ID
      const unverified = jwt.decode(token) as { id?: string; email?: string; type?: string } | null;
      if (!unverified || !unverified.id || unverified.type !== 'pwd_reset') {
        sendErrorResponse(res, 400, 'INVALID_RESET_TOKEN', 'The password reset token is invalid or malformed.', req);
        return;
      }

      const user = await prisma.user.findUnique({
        where: { id: unverified.id },
      });

      if (!user || user.status !== 'active') {
        sendErrorResponse(res, 400, 'INVALID_RESET_TOKEN', 'The password reset token is invalid or user is inactive.', req);
        return;
      }

      // Verify token signature against (jwtSecret + current passwordHash)
      try {
        jwt.verify(token, config.jwtSecret + user.passwordHash);
      } catch {
        sendErrorResponse(res, 400, 'EXPIRED_RESET_TOKEN', 'The password reset token has expired or has already been used.', req);
        return;
      }

      // Hash new password and update
      const newPasswordHash = await bcrypt.hash(newPassword, 12);
      await prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: newPasswordHash },
      });

      logSecurityEvent({
        userId: user.id,
        eventType: 'AUTH_SUCCESS',
        severity: 'INFO',
        targetResource: '/api/v1/auth/reset-password',
        details: { action: 'PASSWORD_RESET_SUCCESSFUL' },
        rawIp: req.ip || req.socket?.remoteAddress,
      });

      logger.info('Password successfully reset for user', { userId: user.id });

      res.status(200).json({
        success: true,
        message: 'Password has been successfully updated. You may now log in with your new password.',
      });
    } catch (err) {
      next(err);
    }
  }
}

export const authController = new AuthController();

