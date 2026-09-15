import path from 'path';
import { Response, NextFunction } from 'express';
import prisma from '../database/client';
import { AuthenticatedRequest } from '../middleware/auth';
import {
  TextScanSchema,
  UrlScanSchema,
  AnalysisIdSchema,
  FeedbackSchema,
  ReportSchema,
  ExplainSchema,
  isValidHttpUrl,
} from '../validation/analyzeSchemas';
import { detectionPipeline } from '../pipeline/orchestrator';
import { reportService } from '../modules/reports/reportService';
import { feedbackService } from '../modules/feedback/feedbackService';
import { scanQueue } from '../workers/scanQueue';
import { secureFileAnalyzer } from '../modules/file';
import { explanationEngine } from '../modules/ai';
import { sendAnalysisResponse, sendErrorResponse } from '../utils/responseFormatter';
import { getRequestId } from '../middleware/requestId';

export class AnalyzeController {
  /**
   * POST /analyze (also supports POST /api/analyze, POST /api/v1/analyze)
   * Canonical Asynchronous Job Entrypoint:
   * POST /analyze → Create analysis job → Return job_id → Queue → Worker → Detection → AI → Database → Completed result
   */
  async createAnalysisJob(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const file = req.file;
      const body = req.body || {};

      // 1. File Analysis Job
      if (file) {
        if (file.size < 1) {
          sendErrorResponse(
            res,
            400,
            'FILE_EMPTY',
            'Uploaded file is empty (0 bytes). Provide a valid file for analysis.',
            req
          );
          return;
        }

        const scan = await prisma.scan.create({
          data: {
            type: 'FILE',
            target: file.originalname,
            status: 'QUEUED',
            userId: req.user?.id || null,
          },
        });

        await scanQueue.addJob({
          type: 'FILE',
          scanId: scan.id,
          tempFilePath: file.path,
          originalName: file.originalname,
          mimeType: file.mimetype || 'application/octet-stream',
        });

        res.status(202).json({
          success: true,
          job_id: scan.id,
          id: scan.id,
          scan_id: scan.id,
          type: 'FILE',
          status: 'QUEUED',
          target: file.originalname,
          message: 'File analysis job created and queued for asynchronous processing.',
          check_status_url: `/api/analysis/${scan.id}`,
        });
        return;
      }

      // 2. URL Analysis Job
      if (body.url || body.type === 'URL') {
        const urlStr = typeof body.url === 'string' ? body.url.trim() : '';
        if (!urlStr) {
          sendErrorResponse(res, 400, 'URL_REQUIRED', 'Target URL is required.', req);
          return;
        }

        if (!isValidHttpUrl(urlStr)) {
          sendErrorResponse(res, 400, 'VALIDATION_ERROR', 'Target URL must be a valid http or https address.', req);
          return;
        }

        const scan = await prisma.scan.create({
          data: {
            type: 'URL',
            target: urlStr,
            status: 'QUEUED',
            userId: req.user?.id || null,
          },
        });

        await scanQueue.addJob({
          type: 'URL',
          scanId: scan.id,
          url: urlStr,
        });

        res.status(202).json({
          success: true,
          job_id: scan.id,
          id: scan.id,
          scan_id: scan.id,
          type: 'URL',
          status: 'QUEUED',
          target: urlStr,
          message: 'URL analysis job created and queued for asynchronous processing.',
          check_status_url: `/api/analysis/${scan.id}`,
        });
        return;
      }

      // 3. AI Explanation Job
      if (body.type === 'AI' || body.type === 'EXPLAIN') {
        const scan = await prisma.scan.create({
          data: {
            type: 'MESSAGE',
            target: (body.content || body.scan_id || 'AI Request').slice(0, 255),
            status: 'QUEUED',
            userId: req.user?.id || null,
          },
        });

        await scanQueue.addJob({
          type: 'AI',
          scanId: scan.id,
          data: body,
          userId: req.user?.id || null,
        });

        res.status(202).json({
          success: true,
          job_id: scan.id,
          id: scan.id,
          scan_id: scan.id,
          type: 'AI',
          status: 'QUEUED',
          message: 'AI request job created and queued for asynchronous processing.',
          check_status_url: `/api/analysis/${scan.id}`,
        });
        return;
      }

      // 4. Text Analysis Job (General or large text)
      const textContent = (body.content || body.text || body.message || '').trim();
      if (textContent) {
        const scan = await prisma.scan.create({
          data: {
            type: 'MESSAGE',
            target: textContent.slice(0, 255),
            status: 'QUEUED',
            userId: req.user?.id || null,
          },
        });

        await scanQueue.addJob({
          type: 'TEXT',
          scanId: scan.id,
          content: textContent,
          userId: req.user?.id || null,
        });

        res.status(202).json({
          success: true,
          job_id: scan.id,
          id: scan.id,
          scan_id: scan.id,
          type: 'TEXT',
          status: 'QUEUED',
          target: textContent.slice(0, 80),
          message: 'Text analysis job created and queued for asynchronous processing.',
          check_status_url: `/api/analysis/${scan.id}`,
        });
        return;
      }

      sendErrorResponse(
        res,
        400,
        'INVALID_ANALYSIS_REQUEST',
        'Provide content (text), url, file, or ai request to create an analysis job.',
        req
      );
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/analyze/text (alias: /api/analyze/message, /api/v1/analyze/message)
   * Pipeline: User Input → Validation → Normalization → Multiple Detectors → Evidence Collection → Risk Engine → AI Explanation → Final Result
   */
  async analyzeText(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      // 1. Validation Layer
      const validated = TextScanSchema.parse(req.body);
      const content = (validated.content || validated.text)!;

      // Allow caller to explicitly request async processing or automatically route if text is large (> 1000 chars)
      const isExplicitAsync = req.query.async === 'true' || req.headers['x-async'] === 'true' || req.body?.async === true;
      const isLargeText = content.length > 1000 && req.query.sync !== 'true';

      if (isExplicitAsync || isLargeText) {
        const scan = await prisma.scan.create({
          data: {
            type: 'MESSAGE',
            target: content.slice(0, 255),
            status: 'QUEUED',
            userId: req.user?.id || null,
          },
        });

        await scanQueue.addJob({
          type: 'TEXT',
          scanId: scan.id,
          content,
          userId: req.user?.id || null,
        });

        res.status(202).json({
          success: true,
          job_id: scan.id,
          id: scan.id,
          scan_id: scan.id,
          type: 'TEXT',
          status: 'QUEUED',
          message: isLargeText
            ? 'Large text analysis job created and queued for asynchronous processing.'
            : 'Text analysis job created and queued for asynchronous processing.',
          check_status_url: `/api/analysis/${scan.id}`,
          target: content.slice(0, 80),
        });
        return;
      }

      // 2. Full Multi-Layer Scam Detection Pipeline (Synchronous by default)
      const result = await detectionPipeline.execute({
        type: 'TEXT',
        rawContent: content,
        userId: req.user?.id || null,
      });

      sendAnalysisResponse(
        res,
        {
          ...result,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          mode: 'text',
          input_snippet: content.length > 80 ? `${content.slice(0, 80)}...` : content,
        },
        req
      );
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/analyze/url (alias: /api/urls/scan, /api/v1/urls/scan)
   * Pipeline: Validation → Multi-Detector URL Inspection → Risk Engine → Database
   */
  async analyzeUrl(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      // 1. Validation Layer
      const validated = UrlScanSchema.parse(req.body);
      const targetUrl = validated.url.trim();

      // Check for synchronous analysis request (?sync=true)
      const isSync = req.query.sync === 'true' || req.headers['x-sync'] === 'true';

      if (isSync) {
        // Execute synchronously via Detection Pipeline
        const result = await detectionPipeline.execute({
          type: 'URL',
          rawContent: targetUrl,
          userId: req.user?.id || null,
        });

        sendAnalysisResponse(
          res,
          {
            ...result,
            url_details: {
              url: targetUrl,
              domain: result.technical_evidence?.extracted_urls?.[0] || targetUrl,
            },
          },
          req
        );
        return;
      }

      // Default Asynchronous queue processing
      const scan = await prisma.scan.create({
        data: {
          type: 'URL',
          target: targetUrl,
          status: 'QUEUED',
          userId: req.user?.id || null,
        },
      });

      await scanQueue.addJob({
        type: 'URL',
        scanId: scan.id,
        url: targetUrl,
      });

      res.status(202).json({
        success: true,
        job_id: scan.id,
        id: scan.id,
        scan_id: scan.id,
        status: 'QUEUED',
        message: 'URL successfully submitted and enqueued for security analysis.',
        url: targetUrl,
        check_status_url: `/api/analysis/${scan.id}`,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/analyze/file (alias: /api/files/scan, /api/v1/files/scan)
   * Pipeline: Validation → File Storage → Background Scan Worker → Multi-Engine Analyzer
   */
  async analyzeFile(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.file) {
        sendErrorResponse(
          res,
          400,
          'FILE_REQUIRED',
          'No file was uploaded in request. Send multipart/form-data with field name "file".',
          req
        );
        return;
      }

      const file = req.file;

      // Check if caller requests direct synchronous sandboxed analysis
      if (req.query.sync === 'true' || req.headers['x-sync-analysis'] === 'true') {
        const analysis = await secureFileAnalyzer.analyze(file.path, file.originalname, file.mimetype, {
          autoCleanup: true,
        });

        const scan = await prisma.scan.create({
          data: {
            type: 'FILE',
            target: file.originalname,
            status: 'COMPLETED',
            riskScore: analysis.risk_score,
            riskLevel:
              analysis.classification === 'Critical Risk'
                ? 'MALICIOUS'
                : analysis.classification === 'High Risk'
                ? 'HIGH_RISK'
                : analysis.classification === 'Suspicious'
                ? 'SUSPICIOUS'
                : 'SAFE',
            threatConfidence: 'HIGH',
            scanDurationMs: analysis.execution_time_ms,
            userId: req.user?.id || null,
            completedAt: new Date(),
            fileRecord: {
              create: {
                originalName: file.originalname,
                sanitizedName: analysis.sanitized_name,
                mimeType: file.mimetype,
                detectedMimeType: analysis.evidence.magic_bytes.detected_mime,
                sizeBytes: analysis.file_size,
                extension: path.extname(analysis.sanitized_name).replace('.', '').toLowerCase(),
                hashes: {
                  create: {
                    sha256: analysis.evidence.file_hashes.sha256,
                    sha1: analysis.evidence.file_hashes.sha1,
                    md5: analysis.evidence.file_hashes.md5,
                  },
                },
              },
            },
            scanResult: {
              create: {
                summary: analysis.evidence.summary,
                safeFactors: JSON.stringify([]),
                recommendations: JSON.stringify([analysis.recommended_action]),
              },
            },
            detections: {
              create: analysis.detected_indicators.map((ind, i) => ({
                engine: 'SecureFileAnalyzer',
                category: 'file_security',
                severity: analysis.risk_score >= 80 ? 'critical' : analysis.risk_score >= 60 ? 'high' : 'medium',
                ruleId: `SEC-FILE-${i + 1}`,
                title: ind.split(':')[0] || 'Security Indicator',
                description: ind,
              })),
            },
          },
        });

        const structuredExplanation = await explanationEngine.generateStructuredExplanation({
          targetType: 'FILE',
          threatCategory: analysis.risk_score >= 60 ? 'malware_hazard' : 'safe_content',
          riskScore: analysis.risk_score,
          classification: analysis.classification as any,
          indicators: analysis.detected_indicators,
          rawContentSnippet: file.originalname,
        });

        sendAnalysisResponse(
          res,
          {
            analysis_id: scan.id,
            id: scan.id,
            scan_id: scan.id,
            status: 'COMPLETED',
            file_type: analysis.file_type,
            file_size: analysis.file_size,
            detected_indicators: analysis.detected_indicators,
            risk_score: analysis.risk_score,
            classification: analysis.classification,
            evidence: analysis.evidence,
            recommended_action: analysis.recommended_action,
            explanation: structuredExplanation,
            ai_explanation: structuredExplanation.why_suspicious,
          },
          req
        );
        return;
      }

      // Default Asynchronous Queued Analysis
      const scan = await prisma.scan.create({
        data: {
          type: 'FILE',
          target: file.originalname,
          status: 'QUEUED',
          userId: req.user?.id || null,
        },
      });

      await scanQueue.addJob({
        type: 'FILE',
        scanId: scan.id,
        tempFilePath: file.path,
        originalName: file.originalname,
        mimeType: file.mimetype,
      });

      res.status(202).json({
        success: true,
        job_id: scan.id,
        id: scan.id,
        scan_id: scan.id,
        status: 'QUEUED',
        message: 'File successfully accepted and queued for security scanning.',
        file_name: file.originalname,
        size_bytes: file.size,
        check_status_url: `/api/analysis/${scan.id}`,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/analysis/:id (alias: /api/scans/:id, /api/v1/scans/:id)
   * Retrieves unified analysis record across all threat modalities (TEXT, URL, FILE, QR)
   */
  async getAnalysisById(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const validated = AnalysisIdSchema.parse(req.params);
      const id = validated.id;

      const scan = await prisma.scan.findUnique({
        where: { id },
        include: {
          fileRecord: {
            include: { hashes: true },
          },
          urlScan: true,
          scanResult: true,
          evidenceRecord: true,
          detections: true,
        },
      });

      if (!scan) {
        sendErrorResponse(
          res,
          404,
          'SCAN_NOT_FOUND',
          `Analysis record with ID '${id}' does not exist.`,
          req
        );
        return;
      }

      // If failed
      if (scan.status === 'FAILED') {
        res.status(200).json({
          success: false,
          error_code: 'ANALYSIS_FAILED',
          message: scan.errorMessage || 'Analysis processing encountered a failure.',
          request_id: getRequestId(req),
          job_id: scan.id,
          id: scan.id,
          scan_id: scan.id,
          type: scan.type,
          status: 'FAILED',
          target: scan.target,
          error: {
            code: 'ANALYSIS_FAILED',
            message: scan.errorMessage || 'Analysis processing encountered a failure.',
          },
          errorMessage: scan.errorMessage,
          created_at: scan.createdAt,
        });
        return;
      }

      // If still processing or queued
      if (scan.status === 'QUEUED' || scan.status === 'PROCESSING') {
        res.status(200).json({
          success: true,
          job_id: scan.id,
          id: scan.id,
          scan_id: scan.id,
          type: scan.type,
          status: scan.status,
          target: scan.target,
          created_at: scan.createdAt,
          message: 'Analysis is currently in progress. Poll this endpoint to receive finalized results.',
        });
        return;
      }

      // Safe parse JSON arrays
      let safeFactors: string[] = [];
      let recommendations: string[] = [];
      if (scan.scanResult?.safeFactors) {
        try {
          safeFactors = JSON.parse(scan.scanResult.safeFactors);
        } catch {
          safeFactors = [];
        }
      }
      if (scan.scanResult?.recommendations) {
        try {
          recommendations = JSON.parse(scan.scanResult.recommendations);
        } catch {
          recommendations = [];
        }
      }

      // Score classification
      const scoreToClassification = (score: number): string => {
        if (score >= 81) return 'Critical Risk';
        if (score >= 61) return 'High Risk';
        if (score >= 41) return 'Suspicious';
        if (score >= 21) return 'Mild Risk';
        return 'Low Risk';
      };

      const detectedIndicators = scan.detections.map((d) => `${d.title}: ${d.description}`);
      const fileType =
        scan.fileRecord?.detectedMimeType ||
        (scan.fileRecord?.extension ? `${scan.fileRecord.extension.toUpperCase()} File` : 'Binary File');
      const recommendedAction = recommendations[0] || 'Exercise standard digital safety precautions.';

      let structuredExplanation: any;
      if (scan.evidenceRecord) {
        let technicalEvidence: any = {};
        try {
          technicalEvidence = JSON.parse(scan.evidenceRecord.technicalEvidence);
        } catch {
          technicalEvidence = {};
        }

        let uncertaintyNotes: any = null;
        if (scan.evidenceRecord.uncertaintyNotes) {
          try {
            uncertaintyNotes = JSON.parse(scan.evidenceRecord.uncertaintyNotes);
          } catch {
            uncertaintyNotes = { is_uncertain: false, reason: scan.evidenceRecord.uncertaintyNotes, missing_information: [], confidence_level: 'medium' };
          }
        }

        structuredExplanation = {
          why_suspicious: technicalEvidence.why_suspicious || scan.evidenceRecord.summary || scan.scanResult?.summary || '',
          triggered_signals: scan.detections.map((d) => ({
            signal: d.title,
            detail: d.description,
            severity: d.severity,
            source_detector: d.engine,
          })),
          scam_type: technicalEvidence.scam_type || {
            category: scan.threatCategory || 'threat',
            name: scan.threatCategory || 'Security Threat',
            description: scan.scanResult?.summary || '',
            threat_level: scan.riskLevel,
          },
          actionable_advice: recommendations,
          uncertainty_notes: uncertaintyNotes || {
            is_uncertain: false,
            reason: '',
            missing_information: [],
            confidence_level: scan.threatConfidence === 'HIGH' ? 'high' : 'medium',
          },
          grounded_in_evidence: true,
          evidence_summary: scan.evidenceRecord.summary || '',
          verified_signal_count: scan.detections.length,
          unverified_claims_filtered: 0,
          summary: scan.evidenceRecord.summary || scan.scanResult?.summary || '',
          aiExplanation: technicalEvidence.why_suspicious || scan.evidenceRecord.summary || scan.scanResult?.summary || '',
          recommended_actions: recommendations,
          recommendedActions: recommendations,
          safe_factors: safeFactors,
          generated_by: 'grounded_rules_engine',
          ai_generated: false,
          engine_version: '2.0.0',
          timestamp: scan.completedAt ? scan.completedAt.toISOString() : new Date().toISOString(),
        };
      } else {
        structuredExplanation = await explanationEngine.generateStructuredExplanation({
          targetType: (scan.type as any) || 'TEXT',
          threatCategory: scan.type === 'FILE'
            ? (scan.riskScore >= 60 ? 'malware_hazard' : 'safe_content')
            : (scan.riskScore >= 60 ? 'phishing' : 'safe_content'),
          riskScore: scan.riskScore,
          classification: scoreToClassification(scan.riskScore) as any,
          threatLevel: scan.riskLevel as any,
          confidenceScore: scan.threatConfidence === 'HIGH' ? 85 : 70,
          indicators: detectedIndicators,
          rawContentSnippet: scan.target.slice(0, 100),
        });
      }

      // Format and send standardized analysis response
      sendAnalysisResponse(
        res,
        {
          analysis_id: scan.id,
          job_id: scan.id,
          id: scan.id,
          scan_id: scan.id,
          type: scan.type,
          status: scan.status,
          target: scan.target,
          threat_level: scan.riskLevel,
          risk_level: scan.riskLevel.toLowerCase(),
          risk_score: scan.riskScore,
          classification: scoreToClassification(scan.riskScore),
          file_type: scan.type === 'FILE' ? fileType : undefined,
          file_size: scan.type === 'FILE' ? scan.fileRecord?.sizeBytes || 0 : undefined,
          detected_indicators: detectedIndicators,
          recommended_action: recommendedAction,
          explanation: structuredExplanation,
          ai_explanation: structuredExplanation.why_suspicious,
          threat_confidence: scan.threatConfidence,
          scan_duration_ms: scan.scanDurationMs,
          summary: scan.scanResult?.summary,
          evidence: {
            summary: scan.scanResult?.summary || '',
            indicators: detectedIndicators,
            file_details: scan.fileRecord
              ? {
                  originalName: scan.fileRecord.originalName,
                  sanitizedName: scan.fileRecord.sanitizedName,
                  mimeType: scan.fileRecord.mimeType,
                  detectedMimeType: scan.fileRecord.detectedMimeType,
                  sizeBytes: scan.fileRecord.sizeBytes,
                  extension: scan.fileRecord.extension,
                  hashes: scan.fileRecord.hashes
                    ? {
                        sha256: scan.fileRecord.hashes.sha256,
                        sha1: scan.fileRecord.hashes.sha1,
                        md5: scan.fileRecord.hashes.md5,
                      }
                    : undefined,
                }
              : undefined,
            detections: scan.detections.map((d) => ({
              engine: d.engine,
              category: d.category,
              severity: d.severity,
              ruleId: d.ruleId,
              title: d.title,
              description: d.description,
              details: d.details ? JSON.parse(d.details) : undefined,
            })),
          },
          file_details: scan.fileRecord
            ? {
                originalName: scan.fileRecord.originalName,
                sanitizedName: scan.fileRecord.sanitizedName,
                mimeType: scan.fileRecord.mimeType,
                detectedMimeType: scan.fileRecord.detectedMimeType,
                sizeBytes: scan.fileRecord.sizeBytes,
                extension: scan.fileRecord.extension,
                hashes: scan.fileRecord.hashes
                  ? {
                      sha256: scan.fileRecord.hashes.sha256,
                      sha1: scan.fileRecord.hashes.sha1,
                      md5: scan.fileRecord.hashes.md5,
                    }
                  : undefined,
              }
            : undefined,
          url_details: scan.urlScan
            ? {
                url: scan.urlScan.url,
                normalizedUrl: scan.urlScan.normalizedUrl,
                domain: scan.urlScan.domain,
                ipAddress: scan.urlScan.ipAddress,
                isHttps: scan.urlScan.isHttps,
                hasRedirects: scan.urlScan.hasRedirects,
                redirectCount: scan.urlScan.redirectCount,
              }
            : undefined,
          detections: scan.detections.map((d) => ({
            engine: d.engine,
            category: d.category,
            severity: d.severity,
            ruleId: d.ruleId,
            title: d.title,
            description: d.description,
            details: d.details ? JSON.parse(d.details) : undefined,
          })),
          safe_factors: safeFactors,
          recommendations: recommendations,
          created_at: scan.createdAt,
          completed_at: scan.completedAt,
          error_message: scan.errorMessage,
        },
        req
      );
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/reports (alias: /api/v1/reports)
   * Pipeline: Validation → User Reports Module → Database
   */
  async submitReport(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const validated = ReportSchema.parse(req.body);
      const report = await reportService.createReport({
        scamType: validated.scamType,
        target: validated.target,
        description: validated.description,
        userId: req.user?.id || null,
      });

      res.status(201).json({
        success: true,
        message: 'Scam report submitted successfully and queued for intelligence review.',
        report_id: report.id,
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/feedback (alias: /api/v1/feedback)
   * Pipeline: Validation → Feedback System → AI Engine Dataset
   */
  async submitFeedback(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const validated = FeedbackSchema.parse(req.body);
      const result = await feedbackService.submitFeedback({
        scan_id: validated.scan_id,
        is_correct: validated.is_correct,
        suggested_category: validated.suggested_category,
        comments: validated.comments,
        userId: req.user?.id || null,
      });

      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/analyze/explain (alias: /api/explain, /api/v1/explain)
   * Grounded AI Explanation Layer: Translates deterministic detection evidence into
   * a structured 5-point explanation without hallucinating or overriding scores.
   */
  async explainAnalysis(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const validated = ExplainSchema.parse(req.body);

      // Support asynchronous queueing for expensive AI requests
      const isAsync = req.query.async === 'true' || req.headers['x-async'] === 'true' || req.body?.async === true;
      if (isAsync) {
        const scan = await prisma.scan.create({
          data: {
            type: 'MESSAGE',
            target: (validated.content || validated.scan_id || 'AI Analysis Request').slice(0, 255),
            status: 'QUEUED',
            userId: req.user?.id || null,
          },
        });

        await scanQueue.addJob({
          type: 'AI',
          scanId: scan.id,
          data: validated,
          userId: req.user?.id || null,
        });

        res.status(202).json({
          success: true,
          job_id: scan.id,
          id: scan.id,
          scan_id: scan.id,
          type: 'AI',
          status: 'QUEUED',
          message: 'AI request job created and queued for asynchronous processing.',
          check_status_url: `/api/analysis/${scan.id}`,
        });
        return;
      }

      let targetType: 'TEXT' | 'URL' | 'FILE' | 'QR' = validated.target_type || 'TEXT';
      let threatCategory = validated.threat_category || 'UNKNOWN';
      let riskScore = validated.risk_score ?? 0;
      let indicators: string[] = validated.indicators || [];
      let rawSnippet = validated.content || '';

      // If a scan_id was provided, hydrate from persistent database record
      if (validated.scan_id) {
        const scan = await prisma.scan.findUnique({
          where: { id: validated.scan_id },
          include: { detections: true, scanResult: true, fileRecord: true },
        });

        if (scan) {
          targetType = (scan.type as any) || targetType;
          threatCategory = scan.type === 'FILE' ? 'malware_hazard' : threatCategory;
          riskScore = scan.riskScore ?? riskScore;
          rawSnippet = scan.target || rawSnippet;
          const scanIndicators = scan.detections.map((d) => d.title);
          indicators = Array.from(new Set([...indicators, ...scanIndicators]));
        } else if (!validated.content && (!validated.indicators || validated.indicators.length === 0)) {
          sendErrorResponse(
            res,
            404,
            'SCAN_NOT_FOUND',
            `Scan record '${validated.scan_id}' not found.`,
            req
          );
          return;
        }
      }

      const explanation = await explanationEngine.generateStructuredExplanation({
        targetType,
        threatCategory,
        riskScore,
        indicators,
        rawContentSnippet: rawSnippet.slice(0, 100),
        language: validated.language,
      });

      res.status(200).json({
        success: true,
        explanation,
      });
    } catch (err) {
      next(err);
    }
  }
}

export const analyzeController = new AnalyzeController();
