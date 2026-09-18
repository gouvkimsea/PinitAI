export type SignalSeverity = 'safe' | 'low' | 'medium' | 'high' | 'critical';

export interface EvidenceSignal {
  id: string;
  source: string;              // e.g. 'url_security_detector', 'text_linguistic_detector'
  signalType: string;          // e.g. 'domain_structure', 'typosquatting', 'urgent_tone'
  severity: SignalSeverity;
  reliability: number;         // 0.0 to 1.0: intrinsic historical reliability of source/signal
  confidence: number;          // 0 to 100: detector certainty in this specific extraction
  timestamp: string;           // ISO 8601 string
  explanation: string;         // Human-readable rationale
  score?: number;              // 0 to 100 indicator intensity/threat weight
  correlationGroup?: string;   // Group identifier to dampen co-dependent signals
  rawDetails?: Record<string, any>;
}

export type RiskAssessmentState =
  | 'SAFE_LOW_RISK'
  | 'SUSPICIOUS'
  | 'HIGH_RISK'
  | 'CONFIRMED_MALICIOUS'
  | 'INSUFFICIENT_EVIDENCE';

export interface SignalCorrelationGroup {
  groupId: string;
  signals: EvidenceSignal[];
  primarySignal: EvidenceSignal;
  effectiveScore: number;
  dampenedScoreContribution: number;
}

export interface RiskConfidenceAssessment {
  riskScore: number;              // 0 to 100: How dangerous/suspicious evidence is
  confidenceScore: number;        // 0 to 100: How confident PinIt is in this assessment
  state: RiskAssessmentState;     // 2D state classification
  rawSignals: EvidenceSignal[];
  deCorrelatedSignals: EvidenceSignal[];
  correlationGroups: Record<string, SignalCorrelationGroup>;
  explanationSummary: string;
  uncertaintyNotes?: string;
  recommendedAction: string;
}
