export type AnalysisMode = 'text' | 'image' | 'url' | 'file' | 'qr';

export type RiskLevel = 'safe' | 'suspicious' | 'high_risk';

export type ThreatCategory =
  | 'SAFE'
  | 'PHISHING'
  | 'INVESTMENT_SCAM'
  | 'JOB_SCAM'
  | 'ROMANCE_SCAM'
  | 'FAKE_SHOP'
  | 'IMPERSONATION'
  | 'PAYMENT_SCAM'
  | 'PRIZE_SCAM'
  | 'MALWARE'
  | 'ACCOUNT_TAKEOVER'
  | 'SOCIAL_ENGINEERING'
  | 'OTHER'
  | 'UNKNOWN / NEEDS_REVIEW';

export interface DetectionSignal {
  id: string;
  category: 'urgency' | 'payment' | 'impersonation' | 'url_anomaly' | 'data_harvesting' | 'general' | 'file_hazard' | string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
}

export interface EvidenceBreakdown {
  message_analysis_score: number;
  url_analysis_score: number;
  threat_indicators_score: number;
  reputation_score: number;
  behavioral_score: number;
}

export interface ExplanationSignalItem {
  signal: string;
  detail: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source_detector?: string;
}

export interface ExplanationScamType {
  category: string;
  name: string;
  description: string;
  threat_level: string;
}

export interface ExplanationUncertainty {
  is_uncertain: boolean;
  reason: string;
  missing_information: string[];
  confidence_level: 'very_low' | 'low' | 'medium' | 'high' | 'verified';
}

/** Full 5-part structured AI explanation returned by the backend. */
export interface AiStructuredExplanation {
  /** 1. Why the content is suspicious */
  why_suspicious: string;
  /** 2. Which signals triggered the detection */
  triggered_signals: ExplanationSignalItem[];
  /** 3. What type of scam may be involved */
  scam_type: ExplanationScamType;
  /** 4. What the user should do */
  actionable_advice: string[];
  /** 5. What uncertainty remains */
  uncertainty_notes: ExplanationUncertainty;

  grounded_in_evidence: boolean;
  evidence_summary: string;
  verified_signal_count: number;

  summary: string;
  aiExplanation: string;
  recommended_actions: string[];
  recommendedActions?: string[];
  safe_factors: string[];

  /** 'ai_model' = Gemini LLM generated the narrative; 'grounded_rules_engine' = deterministic fallback */
  generated_by: 'ai_model' | 'grounded_rules_engine';
  /** True when a live LLM call succeeded */
  ai_generated: boolean;
  engine_version: string;
  timestamp: string;
}

export interface AnalysisResult {
  id: string;
  timestamp: string;
  mode: AnalysisMode;
  inputSnippet: string;
  riskLevel: RiskLevel;
  riskScore: number; // 0 to 100
  classification?: 'Low Risk' | 'Mild Risk' | 'Suspicious' | 'High Risk' | 'Critical Risk';
  triggered_detectors?: string[];
  recommended_action?: string;
  threatCategory?: ThreatCategory;
  title: string;
  summary: string;
  aiExplanation?: string;
  /** Full structured 5-part explanation from backend pipeline */
  structuredExplanation?: AiStructuredExplanation;
  signals: DetectionSignal[];
  recommendedActions: string[];
  confidenceScore: number;
  evidenceBreakdown?: EvidenceBreakdown;
  details: {
    indicatorsFound: number;
    safeFactors: string[];
    domainEvaluated?: string;
    detectedType?: string;
    fileName?: string;
    fileSize?: string;
    qrPayload?: string;
    sha256?: string;
    entropy?: number;
  };
}


/** The 4 structured feedback types */
export type FeedbackType =
  | 'correct_detection'
  | 'incorrect_detection'
  | 'report_scam'
  | 'not_sure';

/** Allowed user-reportable categories (mirrors backend FEEDBACK_CATEGORIES) */
export type FeedbackCategory =
  | 'SAFE'
  | 'PHISHING'
  | 'INVESTMENT_SCAM'
  | 'JOB_SCAM'
  | 'ROMANCE_SCAM'
  | 'FAKE_SHOP'
  | 'IMPERSONATION'
  | 'PAYMENT_SCAM'
  | 'PRIZE_SCAM'
  | 'MALWARE'
  | 'ACCOUNT_TAKEOVER'
  | 'SOCIAL_ENGINEERING'
  | 'OTHER';

/** Structured feedback submission payload (new API) */
export interface FeedbackSubmission {
  /** ID of the analysis being reviewed */
  analysisId?: string;
  /** Feedback type */
  feedbackType?: FeedbackType;
  /** User's suggested category */
  reportedCategory?: FeedbackCategory;
  /** Optional free-text explanation */
  explanation?: string;
  /** Optional snippet of the analyzed content */
  targetSnippet?: string;
  /** Risk score at the time of analysis */
  riskScoreAtTime?: number;
  /** Legacy compat */
  isCorrect?: boolean;
  suggestedCategory?: string;
  comments?: string;
  scanId?: string;
}

/** Response from the feedback API */
export interface FeedbackResult {
  success: boolean;
  message: string;
  feedback_id?: string;
  duplicate?: boolean;
}

export interface TrainingSample {
  id: string;
  content: string;
  content_type: string;
  language: string;
  category: string;
  risk_score: number;
  source: string;
  verified: boolean;
  created_at: string;
}

export interface AdminStats {
  total_scans: number;
  scams_detected: number;
  high_risk_urls: number;
  false_positive_rate: number;
  most_common_threat: string;
  category_distribution: Record<string, number>;
  language_distribution: Record<string, number>;
}

export interface ModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  false_positives: number;
  false_negatives: number;
  false_positive_rate?: number;
  false_negative_rate?: number;
  total_evaluated: number;
}

export interface SampleItem {
  id: string;
  mode: AnalysisMode;
  title: string;
  badge: string;
  content: string;
  imageUrl?: string;
  imageFileName?: string;
  fileName?: string;
  fileSize?: string;
  expectedRisk: RiskLevel;
}

export type Language = 'en' | 'km';
