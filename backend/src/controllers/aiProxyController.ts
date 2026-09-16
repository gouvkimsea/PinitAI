import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import prisma from '../database/client';
import { config } from '../config';
import { logger } from '../utils/logger';
import fs from 'fs';
import { sendAnalysisResponse, sendErrorResponse } from '../utils/responseFormatter';

export class AiProxyController {
  private get aiBase(): string {
    return config.aiEngineUrl.replace(/\/+$/, '');
  }

  /**
   * POST /api/v1/analyze/message
   * Proxies message to Python FastAPI and logs scan to database.
   */
  async analyzeMessage(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { content } = req.body;
      if (!content || typeof content !== 'string' || !content.trim()) {
        sendErrorResponse(res, 400, 'CONTENT_REQUIRED', 'Content cannot be empty.', req);
        return;
      }

      // Forward to Python AI Engine
      const aiRes = await fetch(`${this.aiBase}/api/analyze/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
      });

      if (!aiRes.ok) {
        const errData = await aiRes.json().catch(() => ({}));
        sendErrorResponse(
          res,
          aiRes.status,
          'AI_ENGINE_ERROR',
          (errData as any).detail || 'AI engine failed to analyze message.',
          req
        );
        return;
      }

      const data = (await aiRes.json()) as any;

      // Persist to relational database for scan history
      try {
        await prisma.scan.create({
          data: {
            id: data.id,
            userId: req.user?.id || null,
            type: 'MESSAGE',
            target: content.slice(0, 255),
            status: 'COMPLETED',
            riskLevel: (data.risk_level || 'UNKNOWN').toUpperCase(),
            riskScore: data.risk_score || 0,
            threatConfidence: (data.confidence_score || 0) >= 70 ? 'HIGH' : 'MEDIUM',
            scanResult: {
              create: {
                summary: data.summary || 'Message security analysis complete.',
                totalEngines: 1,
                maliciousEngines: (data.risk_score || 0) >= 60 ? 1 : 0,
                suspiciousEngines: (data.risk_score || 0) >= 40 && (data.risk_score || 0) < 60 ? 1 : 0,
                cleanEngines: (data.risk_score || 0) < 40 ? 1 : 0,
                safeFactors: JSON.stringify(data.technical_evidence?.safe_factors || []),
                recommendations: JSON.stringify(data.recommended_actions || []),
              },
            },
            detections: {
              create: (data.signals || []).map((s: any, idx: number) => ({
                engine: 'FastApiMessageEngine',
                category: s.category || 'anomaly',
                severity: s.severity || 'medium',
                ruleId: s.id || `SIG-${idx + 1}`,
                title: s.title || 'Signal detected',
                description: s.description || '',
              })),
            },
          },
        });
      } catch (dbErr) {
        logger.warn('Could not persist message scan to database', { error: (dbErr as Error).message });
      }

      sendAnalysisResponse(res, data, req);
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/analyze/qr
   * Proxies QR code image/base64/text to Python FastAPI and logs scan to database.
   */
  async analyzeQr(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const file = req.file;
      const { image_base64, raw_text } = req.body;

      let aiRes: globalThis.Response;

      if (file) {
        const fileBuffer = await fs.promises.readFile(file.path);
        const blob = new Blob([fileBuffer], { type: file.mimetype || 'image/png' });
        const formData = new FormData();
        formData.append('image', blob, file.originalname || 'qr.png');

        aiRes = await fetch(`${this.aiBase}/api/analyze/qr`, {
          method: 'POST',
          body: formData,
        });

        // Cleanup temp file uploaded via multer
        fs.promises.unlink(file.path).catch(() => {});
      } else {
        const formData = new FormData();
        if (image_base64) formData.append('image_base64', image_base64);
        if (raw_text) formData.append('raw_text', raw_text);

        aiRes = await fetch(`${this.aiBase}/api/analyze/qr`, {
          method: 'POST',
          body: formData,
        });
      }

      if (!aiRes.ok) {
        const errData = await aiRes.json().catch(() => ({}));
        sendErrorResponse(
          res,
          aiRes.status,
          'AI_ENGINE_ERROR',
          (errData as any).detail || 'AI engine failed to analyze QR code.',
          req
        );
        return;
      }

      const data = (await aiRes.json()) as any;

      // Persist to relational database for scan history
      try {
        await prisma.scan.create({
          data: {
            id: data.id,
            userId: req.user?.id || null,
            type: 'QR',
            target: data.input_snippet ? data.input_snippet.slice(0, 255) : 'QR Code Matrix Scan',
            status: 'COMPLETED',
            riskLevel: (data.risk_level || 'UNKNOWN').toUpperCase(),
            riskScore: data.risk_score || 0,
            threatConfidence: (data.confidence_score || 0) >= 70 ? 'HIGH' : 'MEDIUM',
            scanResult: {
              create: {
                summary: data.summary || 'QR code quarantine analysis complete.',
                totalEngines: 1,
                maliciousEngines: (data.risk_score || 0) >= 60 ? 1 : 0,
                suspiciousEngines: (data.risk_score || 0) >= 40 && (data.risk_score || 0) < 60 ? 1 : 0,
                cleanEngines: (data.risk_score || 0) < 40 ? 1 : 0,
                safeFactors: JSON.stringify(data.technical_evidence?.safe_factors || []),
                recommendations: JSON.stringify(data.recommended_actions || []),
              },
            },
          },
        });
      } catch (dbErr) {
        logger.warn('Could not persist QR scan to database', { error: (dbErr as Error).message });
      }

      sendAnalysisResponse(res, data, req);
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/feedback
   * Forwards accuracy rating to Python FastAPI.
   */
  async submitFeedback(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const aiRes = await fetch(`${this.aiBase}/api/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body),
      });

      const data = await aiRes.json();
      res.status(aiRes.status).json(data);
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/admin/stats
   */
  async getAdminStats(_req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const aiRes = await fetch(`${this.aiBase}/api/admin/stats`, {
        headers: {
          'X-Admin-Key': config.adminApiKey,
        },
      });
      const data = await aiRes.json();
      res.status(aiRes.status).json(data);
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/admin/metrics
   */
  async getAdminMetrics(_req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const aiRes = await fetch(`${this.aiBase}/api/admin/metrics`, {
        headers: {
          'X-Admin-Key': config.adminApiKey,
        },
      });
      const data = await aiRes.json();
      res.status(aiRes.status).json(data);
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/v1/admin/dataset
   */
  async getAdminDataset(_req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const aiRes = await fetch(`${this.aiBase}/api/admin/dataset`, {
        headers: {
          'X-Admin-Key': config.adminApiKey,
        },
      });
      const data = await aiRes.json();
      res.status(aiRes.status).json(data);
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/v1/admin/dataset/verify/:id
   */
  async verifyDatasetItem(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const aiRes = await fetch(`${this.aiBase}/api/admin/dataset/verify/${id}`, {
        method: 'POST',
        headers: {
          'X-Admin-Key': config.adminApiKey,
        },
      });
      const data = await aiRes.json();
      res.status(aiRes.status).json(data);
    } catch (err) {
      next(err);
    }
  }
}

export const aiProxyController = new AiProxyController();
