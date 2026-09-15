import { Request, Response } from 'express';
import { getRequestId } from '../middleware/requestId';

export const CURRENT_MODEL_VERSION = '2.1.0';

/**
 * Standard Successful Analysis Payload Contract
 */
export interface StandardAnalysisPayload {
  success: true;
  analysis_id: string;
  risk_score: number;
  classification: string;
  confidence: number | string;
  evidence: {
    summary?: string;
    indicators: string[];
    breakdown?: Record<string, number>;
    technical_details?: Record<string, any>;
    safe_factors?: string[];
    [key: string]: any;
  };
  detectors: Array<{
    name: string;
    type?: string;
    score?: number;
    severity?: string;
    triggered?: boolean;
    description?: string;
    [key: string]: any;
  }> | string[];
  recommendation: string;
  created_at: string;
  model_version: string;
  cached?: boolean;

  // Backward-compatibility properties
  id?: string;
  scan_id?: string;
  job_id?: string;
  status?: string;
  type?: string;
  target?: string;
  threat_level?: string;
  risk_level?: string;
  threat_category?: string;
  title?: string;
  summary?: string;
  ai_explanation?: string;
  explanation?: any;
  signals?: any[];
  recommended_actions?: string[];
  recommended_action?: string;
  recommendedActions?: string[];
  safe_factors?: string[];
  detected_indicators?: string[];
  technical_evidence?: any;
  confidence_score?: number;
  detected_patterns?: string[];
  suspicious_phrases?: string[];
  scam_category?: string;
  severity?: string;
  file_type?: string;
  file_size?: number;
  file_details?: any;
  url_details?: any;
  scan_duration_ms?: number;
  timestamp?: string;
  mode?: string;
  input_snippet?: string;
  [key: string]: any;
}

/**
 * Standard Error Payload Contract
 */
export interface StandardErrorPayload {
  success: false;
  error_code: string;
  message: string;
  request_id: string;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
}

/**
 * Derives a human-friendly classification string from a numeric risk score
 */
export function deriveClassification(score: number): string {
  if (score >= 81) return 'Critical Risk';
  if (score >= 61) return 'High Risk';
  if (score >= 41) return 'Suspicious';
  if (score >= 21) return 'Mild Risk';
  return 'Low Risk';
}

/**
 * Formats a successful analysis result into the standardized 10-key contract.
 * Also attaches backward-compatible properties so legacy tests and frontend components operate smoothly.
 */
export function formatAnalysisResponse(
  raw: Record<string, any>,
  _req?: Request
): StandardAnalysisPayload {
  const analysisId = String(raw.analysis_id || raw.id || raw.scan_id || raw.job_id || '');
  const riskScore = typeof raw.risk_score === 'number' ? raw.risk_score : (typeof raw.riskScore === 'number' ? raw.riskScore : 0);
  const classification = String(raw.classification || deriveClassification(riskScore));

  const confidence = raw.confidence !== undefined
    ? raw.confidence
    : (raw.confidence_score !== undefined
      ? raw.confidence_score
      : (raw.threatConfidence || (riskScore >= 70 ? 'HIGH' : 'MEDIUM')));

  // Format evidence object
  let evidenceObj: any = { indicators: [] };
  if (raw.evidence && typeof raw.evidence === 'object') {
    evidenceObj = {
      summary: raw.evidence.summary || raw.summary || '',
      indicators: Array.isArray(raw.evidence.indicators)
        ? raw.evidence.indicators
        : (Array.isArray(raw.detected_indicators) ? raw.detected_indicators : []),
      breakdown: raw.evidence.breakdown || raw.evidence_breakdown || {},
      technical_details: raw.evidence.technical_details || raw.technical_evidence || raw.file_details || raw.url_details || {},
      safe_factors: Array.isArray(raw.safe_factors) ? raw.safe_factors : (Array.isArray(raw.evidence.safe_factors) ? raw.evidence.safe_factors : []),
    };
  } else {
    evidenceObj = {
      summary: raw.summary || '',
      indicators: Array.isArray(raw.detected_indicators)
        ? raw.detected_indicators
        : (Array.isArray(raw.indicators) ? raw.indicators : []),
      breakdown: raw.evidence_breakdown || {},
      technical_details: raw.technical_evidence || raw.file_details || raw.url_details || {},
      safe_factors: Array.isArray(raw.safe_factors) ? raw.safe_factors : [],
    };
  }

  // Format detectors array
  let detectorsList: any[] = [];
  if (Array.isArray(raw.detectors) && raw.detectors.length > 0) {
    detectorsList = raw.detectors.map((d: any) => {
      if (typeof d === 'string') return { name: d, triggered: true };
      return {
        name: d.engine || d.name || d.title || 'Detector',
        type: d.category || d.type || 'security',
        severity: d.severity || 'low',
        score: d.score,
        triggered: d.triggered !== false,
        description: d.description,
      };
    });
  } else if (Array.isArray(raw.detections) && raw.detections.length > 0) {
    detectorsList = raw.detections.map((d: any) => ({
      name: d.engine || d.title || 'Detector',
      type: d.category || 'security',
      severity: d.severity || 'medium',
      score: d.score,
      triggered: true,
      description: d.description,
    }));
  } else if (Array.isArray(raw.triggered_detectors) && raw.triggered_detectors.length > 0) {
    detectorsList = raw.triggered_detectors.map((name: string) => ({
      name,
      triggered: true,
    }));
  } else if (Array.isArray(raw.detectors_evaluated)) {
    detectorsList = raw.detectors_evaluated.map((name: string) => ({
      name,
      triggered: (raw.triggered_detectors || []).includes(name),
    }));
  }

  // Primary recommendation string
  let recommendation = 'Exercise standard digital safety precautions.';
  if (typeof raw.recommendation === 'string' && raw.recommendation.trim().length > 0) {
    recommendation = raw.recommendation.trim();
  } else if (typeof raw.recommended_action === 'string' && raw.recommended_action.trim().length > 0) {
    recommendation = raw.recommended_action.trim();
  } else if (Array.isArray(raw.recommendations) && raw.recommendations.length > 0) {
    recommendation = String(raw.recommendations[0]);
  } else if (Array.isArray(raw.recommended_actions) && raw.recommended_actions.length > 0) {
    recommendation = String(raw.recommended_actions[0]);
  }

  const createdAt = raw.created_at
    ? (typeof raw.created_at === 'string' ? raw.created_at : new Date(raw.created_at).toISOString())
    : (raw.createdAt ? new Date(raw.createdAt).toISOString() : new Date().toISOString());

  const modelVersion = raw.model_version || CURRENT_MODEL_VERSION;

  const standardResponse: StandardAnalysisPayload = {
    // 10 Mandatory Standardization Fields
    success: true,
    analysis_id: analysisId,
    risk_score: riskScore,
    classification,
    confidence,
    evidence: evidenceObj,
    detectors: detectorsList,
    recommendation,
    created_at: createdAt,
    model_version: modelVersion,
    cached: raw.cached !== undefined ? Boolean(raw.cached) : undefined,

    // Backward-Compatible Aliases
    id: analysisId,
    scan_id: analysisId,
    job_id: analysisId,
    status: raw.status || 'COMPLETED',
    type: raw.type,
    target: raw.target,
    threat_level: raw.threat_level || raw.riskLevel || (riskScore >= 80 ? 'MALICIOUS' : riskScore >= 60 ? 'HIGH_RISK' : riskScore >= 40 ? 'SUSPICIOUS' : 'SAFE'),
    risk_level: (raw.risk_level || raw.threat_level || '').toLowerCase(),
    threat_category: raw.threat_category,
    title: raw.title,
    summary: raw.summary || evidenceObj.summary,
    ai_explanation: raw.ai_explanation || raw.explanation?.why_suspicious,
    explanation: raw.explanation,
    signals: raw.signals || [],
    recommended_actions: raw.recommended_actions || (Array.isArray(raw.recommendations) ? raw.recommendations : [recommendation]),
    recommended_action: recommendation,
    recommendedActions: raw.recommended_actions || (Array.isArray(raw.recommendations) ? raw.recommendations : [recommendation]),
    safe_factors: raw.safe_factors || evidenceObj.safe_factors || [],
    detected_indicators: raw.detected_indicators || evidenceObj.indicators,
    technical_evidence: raw.technical_evidence || evidenceObj.technical_details,
    confidence_score: raw.confidence_score,
    detected_patterns: raw.detected_patterns,
    suspicious_phrases: raw.suspicious_phrases,
    scam_category: raw.scam_category,
    severity: raw.severity,
    file_type: raw.file_type,
    file_size: raw.file_size,
    file_details: raw.file_details || raw.fileRecord,
    url_details: raw.url_details || raw.urlScan,
    scan_duration_ms: raw.scan_duration_ms || raw.scanDurationMs,
    timestamp: raw.timestamp || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    mode: raw.mode,
    input_snippet: raw.input_snippet,
  };

  return standardResponse;
}

/**
 * Formats a standardized error payload with request_id and zero implementation leaks.
 */
export function formatErrorResponse(
  errorCode: string,
  message: string,
  req?: Request,
  details?: any
): StandardErrorPayload {
  const requestId = getRequestId(req);

  return {
    success: false,
    error_code: errorCode,
    message,
    request_id: requestId,
    error: {
      code: errorCode,
      message,
      ...(details !== undefined ? { details } : {}),
    },
  };
}

/**
 * Express helper to send a standardized analysis response
 */
export function sendAnalysisResponse(
  res: Response,
  data: Record<string, any>,
  req?: Request,
  statusCode = 200
): void {
  const formatted = formatAnalysisResponse(data, req);
  res.status(statusCode).json(formatted);
}

/**
 * Express helper to send a standardized error response
 */
export function sendErrorResponse(
  res: Response,
  statusCode: number,
  errorCode: string,
  message: string,
  req?: Request,
  details?: any
): void {
  const formatted = formatErrorResponse(errorCode, message, req, details);
  res.status(statusCode).json(formatted);
}
