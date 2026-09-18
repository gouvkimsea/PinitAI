/**
 * Pinit Message Scam Detection Engine - Types & Contracts
 */

export type MessageRiskLevel =
  | 'CONFIRMED_MALICIOUS'
  | 'HIGHLY_SUSPICIOUS'
  | 'SUSPICIOUS'
  | 'LOW_RISK'
  | 'SAFE'
  | 'UNKNOWN_INSUFFICIENT_EVIDENCE';

export type PatternSeverity = 'low' | 'medium' | 'high' | 'critical';

export type BehavioralPatternType =
  | 'URGENCY'
  | 'THREATS'
  | 'ACCOUNT_SUSPENSION'
  | 'FAKE_REWARDS'
  | 'FAKE_JOBS'
  | 'FAKE_INVESTMENTS'
  | 'FAKE_LOANS'
  | 'FAKE_DELIVERIES'
  | 'FAKE_GOVERNMENT_COMMUNICATION'
  | 'FAKE_BANK_COMMUNICATION'
  | 'FAKE_CUSTOMER_SUPPORT'
  | 'ROMANCE_MANIPULATION'
  | 'PAYMENT_REQUESTS'
  | 'ADVANCE_FEE_REQUESTS'
  | 'OTP_REQUESTS'
  | 'PASSWORD_REQUESTS'
  | 'PIN_REQUESTS'
  | 'BANKING_CREDENTIAL_REQUESTS'
  | 'IDENTITY_DOCUMENT_REQUESTS'
  | 'REMOTE_ACCESS_REQUESTS'
  | 'SUSPICIOUS_DOWNLOADS'
  | 'SUSPICIOUS_LINKS'
  | 'IMPERSONATION'
  | 'FINANCIAL_MANIPULATION'
  | 'FEAR_BASED_MANIPULATION'
  | 'AUTHORITY_IMPERSONATION'
  | 'EXCESSIVE_URGENCY'
  | 'REQUESTS_TO_MOVE_PLATFORM';

export interface CryptoEntity {
  type: 'BTC' | 'ETH' | 'USDT_TRC20' | 'SOL' | 'UNKNOWN';
  address: string;
}

export interface BankAccountEntity {
  bank?: string;
  accountNumber: string;
  raw: string;
}

export interface PaymentHandleEntity {
  provider: 'Bakong' | 'KHQR' | 'ABA' | 'Wing' | 'PayPal' | 'CashApp' | 'Zelle' | 'WeChat' | 'Alipay' | 'Other';
  identifier: string;
}

export interface SocialHandleEntity {
  platform: 'telegram' | 'whatsapp' | 'messenger' | 'instagram' | 'line' | 'tiktok' | 'twitter' | 'other';
  handle: string;
}

export interface ExtractedEntities {
  urls: string[];
  phoneNumbers: string[];
  emailAddresses: string[];
  cryptoAddresses: CryptoEntity[];
  bankAccounts: BankAccountEntity[];
  paymentHandles: PaymentHandleEntity[];
  socialHandles: SocialHandleEntity[];
  brands: string[];
  requestedCredentials: string[];
}

export interface BehavioralPatternMatch {
  id: string;
  patternType: BehavioralPatternType;
  patternName: string;
  severity: PatternSeverity;
  scoreContribution: number;
  title: string;
  description: string;
  matchedPhrases: string[];
}

export interface MessageIntentClassification {
  primaryIntent:
    | 'CREDENTIAL_HARVESTING'
    | 'FINANCIAL_ADVANCE_FEE'
    | 'DECEPTIVE_JOB_RECRUITMENT'
    | 'INVESTMENT_SOLICITATION'
    | 'DELIVERY_SMISHING'
    | 'LOAN_SOLICITATION'
    | 'PRIZE_CLAIM'
    | 'ROMANCE_ICEBREAKER'
    | 'AUTHORITY_COERCION'
    | 'CUSTOMER_SUPPORT_IMPOSTER'
    | 'REMOTE_ACCESS_ATTEMPT'
    | 'OFF_PLATFORM_LURE'
    | 'BENIGN_CONVERSATION'
    | 'UNKNOWN_AMBIGUOUS';
  confidence: number;
  isSolicitation: boolean;
  summary: string;
}

export interface SocialEngineeringAnalysis {
  urgencyLevel: 'NONE' | 'MODERATE' | 'SEVERE';
  fearTactics: boolean;
  authorityClaim: boolean;
  manipulationScore: number;
}

export interface MessageEvidenceItem {
  signal: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details: string;
  matchedSnippet?: string;
}

export interface MessageScamResult {
  riskLevel: MessageRiskLevel;
  riskScore: number; // 0 to 100
  confidence: number; // 0 to 100
  scamCategories: string[];
  indicators: string[];
  extractedEntities: ExtractedEntities;
  behavioralPatterns: BehavioralPatternMatch[];
  intent: MessageIntentClassification;
  socialEngineering: SocialEngineeringAnalysis;
  recommendedAction: string;
  explanation: string;
  evidence: MessageEvidenceItem[];
  language: 'en' | 'km' | 'km-en' | 'unknown';
  normalizedText: string;
  executionTimeMs: number;
}
