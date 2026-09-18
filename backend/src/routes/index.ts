import { Router, Request, Response, NextFunction } from 'express';
import prisma from '../database/client';
import { analyzeController } from '../controllers/analyzeController';
import { fileScanController } from '../controllers/fileScanController';
import { urlScanController } from '../controllers/urlScanController';
import { scanHistoryController } from '../controllers/scanHistoryController';
import { authController } from '../controllers/authController';
import { systemController } from '../controllers/systemController';
import { reportController } from '../controllers/reportController';
import { aiProxyController } from '../controllers/aiProxyController';
import { intelligenceController } from '../controllers/intelligenceController';
import { feedbackController } from '../controllers/feedbackController';
import { retentionController } from '../controllers/retentionController';
import { aiController } from '../controllers/aiController';
import { evaluationController } from '../controllers/evaluationController';
import { fileUpload } from '../middleware/upload';
import {
  secureMulterUpload,
  enforceFileSecurity,
  handleUploadErrors,
} from '../middleware/fileSecurityMiddleware';
import { optionalAuth, requireAuth, requireRole } from '../middleware/auth';
import { authLimiter, standardApiLimiter } from '../middleware/rateLimiter';
import {
  textScanLimiter,
  urlScanLimiter,
  fileScanLimiter,
  aiLimiter,
  reportsLimiter,
  feedbackLimiter,
  enforceTextPayloadLimit,
} from '../middleware/abuseProtection';

export const apiRouter = Router();

// =========================================================================
// Clean Canonical Analysis Pipeline Endpoints
// Pipeline: API → Validation → Detection Services → Risk Engine → AI Explanation → DB
// =========================================================================

/**
 * POST /api/analyze (Canonical Asynchronous Job Creation Architecture)
 * POST /analyze → Create analysis job → Return job_id → Queue → Worker → Detection → AI → Database → Completed result
 */
apiRouter.post(
  '/analyze',
  standardApiLimiter,
  optionalAuth,
  secureMulterUpload.single('file'),
  handleUploadErrors,
  analyzeController.createAnalysisJob.bind(analyzeController)
);
apiRouter.post(
  '/analysis',
  standardApiLimiter,
  optionalAuth,
  secureMulterUpload.single('file'),
  handleUploadErrors,
  analyzeController.createAnalysisJob.bind(analyzeController)
);

/**
 * POST /api/analyze/text (also supports alias POST /api/analyze/message)
 * Bilingual (Khmer + English) scam message detection with multi-signal heuristics,
 * composite risk scoring, and actionable safety guidance.
 */
apiRouter.post(
  '/analyze/text',
  textScanLimiter,
  enforceTextPayloadLimit,
  optionalAuth,
  analyzeController.analyzeText.bind(analyzeController)
);
apiRouter.post(
  '/analyze/message',
  textScanLimiter,
  enforceTextPayloadLimit,
  optionalAuth,
  analyzeController.analyzeMessage.bind(analyzeController)
);
apiRouter.post(
  '/message/analyze',
  textScanLimiter,
  enforceTextPayloadLimit,
  optionalAuth,
  analyzeController.analyzeMessage.bind(analyzeController)
);

/**
 * POST /api/ai/analyze
 * Evaluates content through the 7-layer Hybrid Scam Detection Architecture
 * (Rule Engine + Threat Intel + URL Analysis + Message Analysis + Behavioral Signals + AI Semantic Analysis + Anti-Override Guard)
 */
apiRouter.post(
  '/ai/analyze',
  aiLimiter,
  enforceTextPayloadLimit,
  optionalAuth,
  aiController.analyze.bind(aiController)
);

/**
 * Systematic Evaluation Dataset & Quality Benchmarking Endpoints
 */
apiRouter.get(
  '/evaluation/dataset',
  standardApiLimiter,
  optionalAuth,
  evaluationController.getDatasetInfo.bind(evaluationController)
);
apiRouter.post(
  '/evaluation/benchmark',
  standardApiLimiter,
  optionalAuth,
  evaluationController.runBenchmark.bind(evaluationController)
);
apiRouter.get(
  '/evaluation/metrics',
  standardApiLimiter,
  optionalAuth,
  evaluationController.getLatestMetrics.bind(evaluationController)
);


/**
 * POST /api/analyze/url (also supports alias POST /api/urls/scan)
 * Comprehensive URL security inspection: SSRF prevention, brand impersonation,
 * phishing heuristics, and threat intelligence.
 */
apiRouter.post(
  '/analyze/url',
  urlScanLimiter,
  optionalAuth,
  analyzeController.analyzeUrl.bind(analyzeController)
);
apiRouter.post(
  '/urls/scan',
  urlScanLimiter,
  optionalAuth,
  urlScanController.submitUrlScan.bind(urlScanController)
);

/**
 * POST /api/analyze/file (also supports alias POST /api/files/scan)
 * Multi-engine file analysis: cryptographic hashing, magic byte verification,
 * static executable/macro heuristics, and antivirus scanning.
 */
apiRouter.post(
  '/analyze/file',
  fileScanLimiter,
  optionalAuth,
  secureMulterUpload.single('file'),
  handleUploadErrors,
  enforceFileSecurity,
  analyzeController.analyzeFile.bind(analyzeController)
);
apiRouter.post(
  '/files/scan',
  fileScanLimiter,
  optionalAuth,
  secureMulterUpload.single('file'),
  handleUploadErrors,
  enforceFileSecurity,
  fileScanController.submitFileScan.bind(fileScanController)
);
apiRouter.post(
  '/files/analyze',
  fileScanLimiter,
  optionalAuth,
  secureMulterUpload.single('file'),
  handleUploadErrors,
  enforceFileSecurity,
  (req: Request, res: Response, next: NextFunction) => {
    (req as any).query.sync = 'true';
    return analyzeController.analyzeFile(req as any, res, next);
  }
);

/**
 * POST /api/analyze/explain (also supports alias POST /api/explain)
 * AI Explanation Layer: Translates deterministic detection evidence into
 * a structured 5-point explanation without hallucinating.
 */
apiRouter.post(
  '/analyze/explain',
  aiLimiter,
  optionalAuth,
  analyzeController.explainAnalysis.bind(analyzeController)
);
apiRouter.post(
  '/explain',
  aiLimiter,
  optionalAuth,
  analyzeController.explainAnalysis.bind(analyzeController)
);

/**
 * GET /api/analysis/:id (also supports alias GET /api/scans/:id)
 * Unified analysis record retrieval across all modalities (TEXT, URL, FILE, QR).
 */
apiRouter.get(
  '/analysis/:id',
  optionalAuth,
  analyzeController.getAnalysisById.bind(analyzeController)
);
apiRouter.get(
  '/scans/:id',
  optionalAuth,
  analyzeController.getAnalysisById.bind(analyzeController)
);

/**
 * Specific file and URL scan poll endpoints (retained for backward compatibility)
 */
apiRouter.get(
  '/files/scan/:id',
  optionalAuth,
  fileScanController.getFileScanResult.bind(fileScanController)
);
apiRouter.get(
  '/urls/scan/:id',
  optionalAuth,
  urlScanController.getUrlScanResult.bind(urlScanController)
);

/**
 * POST /api/analyze/qr
 * Deep QR matrix decoder and destination quarantine inspector.
 */
apiRouter.post(
  '/analyze/qr',
  fileScanLimiter,
  optionalAuth,
  fileUpload.single('image'),
  aiProxyController.analyzeQr.bind(aiProxyController)
);

// =========================================================================
// Feedback & Community Reports Layer
// =========================================================================

/**
 * POST /api/v2/feedback  (new structured 4-type feedback)
 * Submit analysis feedback: correct_detection | incorrect_detection | report_scam | not_sure
 * Abuse prevention: express-rate-limit (layer 1) + DB-level duplicate/burst check (layer 2)
 * Storage: AnalysisFeedback table (staging only — never touches ScamPattern or ThreatIntelligence)
 */
apiRouter.post(
  '/v2/feedback',
  feedbackLimiter,
  optionalAuth,
  feedbackController.submitFeedback.bind(feedbackController)
);

/**
 * GET /api/v2/feedback/analysis/:analysisId
 * Public: returns aggregated feedback counts for an analysis (no raw records)
 */
apiRouter.get(
  '/v2/feedback/analysis/:analysisId',
  optionalAuth,
  feedbackController.getAnalysisFeedbackSummary.bind(feedbackController)
);

/**
 * POST /api/feedback  (legacy endpoint — backward compatible)
 * Maps is_correct boolean to correct_detection/incorrect_detection type.
 * Routes through the new feedbackService for consistent persistence.
 */
apiRouter.post(
  '/feedback',
  feedbackLimiter,
  optionalAuth,
  analyzeController.submitFeedback.bind(analyzeController)
);

/**
 * POST /api/reports
 * Submit community scam and threat intelligence report.
 */
apiRouter.post(
  '/reports',
  reportsLimiter,
  optionalAuth,
  analyzeController.submitReport.bind(analyzeController)
);

/**
 * GET /api/reports
 * Admin view of pending community reports.
 */
apiRouter.get(
  '/reports',
  requireAuth,
  requireRole('admin'),
  reportController.listReports.bind(reportController)
);

// =========================================================================
// Scan History Management
// =========================================================================
apiRouter.get(
  '/scans',
  optionalAuth,
  scanHistoryController.listScans.bind(scanHistoryController)
);
apiRouter.delete(
  '/scans/:id',
  requireAuth,
  scanHistoryController.deleteScan.bind(scanHistoryController)
);

// =========================================================================
// System Diagnostics & Health Monitoring
// =========================================================================
apiRouter.get('/health', systemController.getHealth.bind(systemController));
apiRouter.get('/health/database', systemController.getDatabaseHealth.bind(systemController));
apiRouter.get('/health/services', systemController.getServicesHealth.bind(systemController));
apiRouter.get('/health/performance', systemController.getPerformanceMetrics.bind(systemController));
apiRouter.get('/metrics', systemController.getPerformanceMetrics.bind(systemController));
apiRouter.get('/statistics', systemController.getStatistics.bind(systemController));

/**
 * GET /api/models
 * Lists registered active AI/heuristic models and versions in the platform registry.
 */
apiRouter.get('/models', optionalAuth, async (_req: Request, res: Response, next: NextFunction) => {
  try {
    res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=120');
    const models = await prisma.modelVersion.findMany({
      where: { isActive: true },
      orderBy: [{ provider: 'asc' }, { name: 'asc' }],
    });
    res.status(200).json({
      success: true,
      models: models.map((m) => ({
        ...m,
        capabilities: JSON.parse(m.capabilities || '[]'),
      })),
    });
  } catch (err) {
    next(err);
  }
});

// =========================================================================
// Authentication & API Key Management
// =========================================================================
apiRouter.post('/auth/register', authLimiter, authController.register.bind(authController));
apiRouter.post('/auth/login', authLimiter, authController.login.bind(authController));
apiRouter.post('/auth/forgot-password', authLimiter, authController.forgotPassword.bind(authController));
apiRouter.post('/auth/reset-password', authLimiter, authController.resetPassword.bind(authController));
apiRouter.post('/auth/logout', requireAuth, authController.logout.bind(authController));
apiRouter.post('/auth/refresh', requireAuth, authController.refresh.bind(authController));
apiRouter.get('/auth/me', requireAuth, authController.getProfile.bind(authController));
apiRouter.delete('/auth/me', requireAuth, authController.deleteAccount.bind(authController));
apiRouter.post('/auth/api-key/regenerate', requireAuth, authController.regenerateApiKey.bind(authController));

// =========================================================================
// Admin Telemetry & Dataset Verification (FastAPI AI Engine Gateway)
// =========================================================================
apiRouter.get('/admin/stats', requireAuth, requireRole('admin'), aiProxyController.getAdminStats.bind(aiProxyController));
apiRouter.get('/admin/metrics', requireAuth, requireRole('admin'), aiProxyController.getAdminMetrics.bind(aiProxyController));
apiRouter.get('/admin/dataset', requireAuth, requireRole('admin'), aiProxyController.getAdminDataset.bind(aiProxyController));
apiRouter.post(
  '/admin/dataset/verify/:id',
  requireAuth,
  requireRole('admin'),
  aiProxyController.verifyDatasetItem.bind(aiProxyController)
);
apiRouter.delete(
  '/admin/retention/purge',
  requireAuth,
  requireRole('admin'),
  retentionController.purgeExpiredData.bind(retentionController)
);
apiRouter.get(
  '/admin/retention/policy',
  requireAuth,
  requireRole('admin'),
  retentionController.getRetentionPolicy.bind(retentionController)
);

/**
 * GET /api/admin/feedback
 * Admin: list all feedback with optional filters (feedbackType, isReviewed, analysisId, page)
 */
apiRouter.get(
  '/admin/feedback',
  requireAuth,
  requireRole('admin'),
  feedbackController.listFeedback.bind(feedbackController)
);

/**
 * PATCH /api/admin/feedback/:id/review
 * Admin: mark a feedback record as reviewed with optional review note.
 * This is the ONLY way reviewer notes can be added — users cannot call this.
 */
apiRouter.patch(
  '/admin/feedback/:id/review',
  requireAuth,
  requireRole('admin'),
  feedbackController.markReviewed.bind(feedbackController)
);

// =========================================================================
// Structured Scam Intelligence Database & Comparison Service
// =========================================================================

/**
 * GET /api/intelligence/categories
 * List supported scam categories
 */
apiRouter.get(
  '/intelligence/categories',
  optionalAuth,
  intelligenceController.getCategories.bind(intelligenceController)
);

/**
 * POST /api/intelligence/compare
 * Compare submitted content against known scam patterns in the database
 */
apiRouter.post(
  '/intelligence/compare',
  textScanLimiter,
  optionalAuth,
  intelligenceController.compareContent.bind(intelligenceController)
);

/**
 * GET /api/intelligence/patterns
 * Query structured scam intelligence patterns
 */
apiRouter.get(
  '/intelligence/patterns',
  optionalAuth,
  intelligenceController.listPatterns.bind(intelligenceController)
);

/**
 * GET /api/intelligence/patterns/:id
 * Retrieve specific pattern by ID
 */
apiRouter.get(
  '/intelligence/patterns/:id',
  optionalAuth,
  intelligenceController.getPatternById.bind(intelligenceController)
);

/**
 * POST /api/intelligence/patterns
 * Register new scam intelligence pattern (dynamic runtime update)
 */
apiRouter.post(
  '/intelligence/patterns',
  requireAuth,
  requireRole('admin'),
  intelligenceController.createPattern.bind(intelligenceController)
);

/**
 * PUT /api/intelligence/patterns/:id
 * Update scam intelligence pattern
 */
apiRouter.put(
  '/intelligence/patterns/:id',
  requireAuth,
  requireRole('admin'),
  intelligenceController.updatePattern.bind(intelligenceController)
);

/**
 * DELETE /api/intelligence/patterns/:id
 * Delete scam intelligence pattern
 */
apiRouter.delete(
  '/intelligence/patterns/:id',
  requireAuth,
  requireRole('admin'),
  intelligenceController.deletePattern.bind(intelligenceController)
);

/**
 * POST /api/intelligence/seed
 * Seed or reset default scam intelligence catalog
 */
apiRouter.post(
  '/intelligence/seed',
  requireAuth,
  requireRole('admin'),
  intelligenceController.seedCatalog.bind(intelligenceController)
);

/**
 * GET /api/intelligence/rules
 * List modular scam intelligence rules with filtering
 */
apiRouter.get(
  '/intelligence/rules',
  optionalAuth,
  intelligenceController.listRules.bind(intelligenceController)
);

/**
 * GET /api/intelligence/rules/:id
 * Retrieve specific modular rule details, version history, and metrics
 */
apiRouter.get(
  '/intelligence/rules/:id',
  optionalAuth,
  intelligenceController.getRuleById.bind(intelligenceController)
);

/**
 * POST /api/intelligence/rules/:id/toggle
 * Enable or disable a rule at runtime without code changes or restarts
 */
apiRouter.post(
  '/intelligence/rules/:id/toggle',
  requireAuth,
  requireRole('admin'),
  intelligenceController.toggleRule.bind(intelligenceController)
);

/**
 * POST /api/intelligence/rules/:id/test
 * Run automated self-testing fixtures for a specific rule
 */
apiRouter.post(
  '/intelligence/rules/:id/test',
  requireAuth,
  requireRole('admin'),
  intelligenceController.testRule.bind(intelligenceController)
);

/**
 * POST /api/intelligence/rules/test-all
 * Run test suites across all registered rules
 */
apiRouter.post(
  '/intelligence/rules/test-all',
  requireAuth,
  requireRole('admin'),
  intelligenceController.testAllRules.bind(intelligenceController)
);

/**
 * GET /api/intelligence/metrics
 * Performance metrics, evaluation count, latency, and FP/FN stats
 */
apiRouter.get(
  '/intelligence/metrics',
  optionalAuth,
  intelligenceController.getMetrics.bind(intelligenceController)
);

/**
 * POST /api/intelligence/feedback/false-positive
 * Record false positive report
 */
apiRouter.post(
  '/intelligence/feedback/false-positive',
  optionalAuth,
  intelligenceController.reportFalsePositive.bind(intelligenceController)
);

/**
 * POST /api/intelligence/feedback/false-negative
 * Record false negative report
 */
apiRouter.post(
  '/intelligence/feedback/false-negative',
  optionalAuth,
  intelligenceController.reportFalseNegative.bind(intelligenceController)
);

/**
 * POST /api/intelligence/evaluate
 * Evaluate content against multi-signal modular rules enforcing the Anti-Unilateral Principle
 */
apiRouter.post(
  '/intelligence/evaluate',
  textScanLimiter,
  optionalAuth,
  intelligenceController.evaluateModular.bind(intelligenceController)
);

