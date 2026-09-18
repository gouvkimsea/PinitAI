import { RuleCategory } from '../intelligence/rules/types';

export interface SemanticDimensions {
  intent: string;
  context: string;
  manipulation_tactics: string[];
  impersonation: {
    detected: boolean;
    target?: string;
    type?: 'bank' | 'government' | 'executive' | 'support' | 'brand' | 'other';
    confidence: number;
  };
  financial_requests: {
    detected: boolean;
    method?: string; // e.g. "gift_card", "wire_transfer", "crypto", "advance_fee", "overpayment"
    amount?: string;
    currency?: string;
  };
  credential_requests: {
    detected: boolean;
    type?: string; // e.g. "password", "otp", "pin", "seed_phrase", "session_token"
  };
  urgency: {
    level: 'none' | 'low' | 'medium' | 'high' | 'extreme';
    timeframe_claimed?: string;
    reason?: string;
  };
  threats: string[]; // e.g. "account_suspension", "legal_prosecution", "arrest"
  suspicious_instructions: string[]; // e.g. "install_remote_software", "keep_secret", "click_unverified_link"
  social_engineering_patterns: string[]; // e.g. "fear_and_urgency", "fake_reciprocity", "authority_intimidation"
  scam_category: string;
  ambiguity: {
    is_ambiguous: boolean;
    reason: string;
    missing_information: string[];
  };
}

export interface StructuredAiAnalysis {
  classification: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  confidence: number; // 0 to 100
  categories: string[];
  indicators: string[];
  reasoning_summary: string;
  recommended_action: string;
  dimensions: SemanticDimensions;
  uncertainty: {
    is_uncertain: boolean;
    confidence_level: 'very_low' | 'low' | 'medium' | 'high' | 'verified';
    missing_evidence: string[];
  };
  grounding: {
    url_hallucinations_filtered: number;
    intel_hallucinations_filtered: number;
    cot_stripped: boolean;
    deterministic_override_applied: boolean;
    sanitized_prompt_injection?: boolean;
  };
}

export interface HybridEvidencePacket {
  targetType: 'TEXT' | 'URL' | 'FILE' | 'QR';
  rawInputSnippet: string;
  sanitizedInput: string;
  detectedLanguage?: string;
  extractedUrls: string[];
  extractedPhoneNumbers?: string[];

  // 1. Rule Engine Findings
  ruleSignals: {
    triggeredRules: Array<{
      ruleId: string;
      category: RuleCategory | string;
      severity: string;
      description: string;
      snippets: string[];
    }>;
    categoryCount: number;
    highestRuleSeverity: string;
  };

  // 2. Threat Intelligence Findings
  threatIntelSignals: {
    reputationScore?: number;
    knownMalicious: boolean;
    listedOnFeeds: string[]; // e.g. ["openphish", "urlhaus"]
    communityReportCount: number;
  };

  // 3. URL Analysis Findings
  urlSignals?: {
    domain?: string;
    isIpHost?: boolean;
    isLookalike?: boolean;
    impersonatedBrand?: string;
    suspiciousPathOrParams?: boolean;
    redirectionChainCount?: number;
  };

  // 4. Message & Linguistic Analysis Findings
  messageSignals?: {
    linguisticScore?: number;
    detectedBehaviors: string[]; // e.g. ["URGENCY", "THREAT", "OTP_REQUEST"]
    isObfuscated?: boolean;
  };

  // 5. Behavioral Signals
  behavioralSignals: {
    impersonationDetected: boolean;
    impersonatedEntity?: string;
    coerciveUrgency: boolean;
    isolationTactic: boolean;
  };

  // Deterministic Baseline
  deterministicBaseline: {
    preliminaryScore: number;
    preliminarySeverity: 'safe' | 'low' | 'medium' | 'high' | 'critical';
    isConfirmedMalicious: boolean;
  };
}
