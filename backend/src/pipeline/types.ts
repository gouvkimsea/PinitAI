import { ThreatLevel } from '../types';
import { RiskClassification } from '../modules/risk/riskConfig';
import { AiStructuredExplanation } from '../modules/ai/types';

export type InputType = 'TEXT' | 'URL' | 'FILE' | 'QR';

export type DetectorSeverity = 'safe' | 'low' | 'medium' | 'high' | 'critical';

export interface PipelineInput {
  scanId?: string;
  type: InputType;
  rawContent?: string;
  filePath?: string;
  originalFileName?: string;
  mimeType?: string;
  userId?: string | null;
  metadata?: Record<string, any>;
}

export interface NormalizedInput {
  type: InputType;
  raw: string;
  normalizedText?: string;
  deobfuscatedText?: string;
  normalizedUrl?: string;
  urlDomain?: string;
  sanitizedFileName?: string;
  fileExtension?: string;
  fileSizeBytes?: number;
  fileMimeType?: string;
  detectedLanguage?: 'en' | 'km' | 'km-en' | 'unknown';
  extractedUrls: string[];
  extractedPhoneNumbers: string[];
}

export interface DetectorEvidence {
  summary: string;
  indicators: string[];
  details?: Record<string, any>;
}

export interface DetectorResult {
  detector_name: string;
  detector_type: 'text' | 'url' | 'file' | 'pattern' | 'reputation' | 'community' | 'ai' | 'impersonation';
  score: number; // 0 to 100
  severity: DetectorSeverity;
  confidence: number; // 0 to 100
  evidence: DetectorEvidence;
  execution_time_ms: number;
}

export interface EvidenceCollection {
  detectorResults: DetectorResult[];
  totalDetectorsRan: number;
  maliciousCount: number;
  suspiciousCount: number;
  cleanCount: number;
  indicators: string[];
  detectedThreatCategories: string[];
  highestSeverity: DetectorSeverity;
}

export interface PipelineContext {
  scanId: string;
  userId?: string | null;
  startTime: number;
}

export interface IDetector {
  readonly name: string;
  readonly type: DetectorResult['detector_type'];
  readonly enabled: boolean;
  supports(type: InputType): boolean;
  detect(input: NormalizedInput, context: PipelineContext): Promise<DetectorResult | null>;
}

export interface PipelineFinalResult {
  id: string;
  scan_id: string;
  type: InputType;
  target: string;
  status: 'COMPLETED' | 'FAILED' | 'QUEUED' | 'PROCESSING';
  cached?: boolean;
  risk_score: number;
  classification: RiskClassification;
  confidence: number;
  threat_level: ThreatLevel;
  risk_level: string;
  threat_category: string;
  title: string;
  confidence_score: number;
  summary: string;
  ai_explanation: string;
  explanation: AiStructuredExplanation;
  triggered_detectors: string[];
  recommended_action: string;
  detected_patterns?: string[];
  suspicious_phrases?: string[];
  scam_category?: string;
  severity?: string;
  evidence: {
    summary: string;
    indicators: string[];
    breakdown: Record<string, number>;
    criticalRulesTriggered?: string[];
  };
  evidence_breakdown: Record<string, number>;
  detector_results: DetectorResult[];
  detectors_evaluated: string[];
  signals: Array<{
    id: string;
    category: string;
    severity: 'low' | 'medium' | 'high';
    title: string;
    description: string;
  }>;
  recommended_actions: string[];
  safe_factors: string[];
  technical_evidence: Record<string, any>;
  created_at: string;
}
