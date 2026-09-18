export type RuleCategory =
  | 'phishing'
  | 'impersonation'
  | 'financial_fraud'
  | 'payment_fraud'
  | 'credential_theft'
  | 'otp_theft'
  | 'social_engineering'
  | 'fake_employment'
  | 'fake_investment'
  | 'fake_shopping'
  | 'fake_delivery'
  | 'fake_support'
  | 'romance_scams'
  | 'giveaway_scams'
  | 'loan_scams'
  | 'crypto_scams'
  | 'account_takeover'
  | 'malware_delivery'
  | 'malicious_downloads'
  | 'qr_scams';

export const ALL_RULE_CATEGORIES: RuleCategory[] = [
  'phishing',
  'impersonation',
  'financial_fraud',
  'payment_fraud',
  'credential_theft',
  'otp_theft',
  'social_engineering',
  'fake_employment',
  'fake_investment',
  'fake_shopping',
  'fake_delivery',
  'fake_support',
  'romance_scams',
  'giveaway_scams',
  'loan_scams',
  'crypto_scams',
  'account_takeover',
  'malware_delivery',
  'malicious_downloads',
  'qr_scams',
];

export const CATEGORY_DISPLAY_NAMES: Record<RuleCategory, string> = {
  phishing: 'Phishing',
  impersonation: 'Impersonation',
  financial_fraud: 'Financial Fraud',
  payment_fraud: 'Payment Fraud',
  credential_theft: 'Credential Theft',
  otp_theft: 'OTP Theft',
  social_engineering: 'Social Engineering',
  fake_employment: 'Fake Employment',
  fake_investment: 'Fake Investment',
  fake_shopping: 'Fake Shopping',
  fake_delivery: 'Fake Delivery',
  fake_support: 'Fake Support',
  romance_scams: 'Romance Scams',
  giveaway_scams: 'Giveaway Scams',
  loan_scams: 'Loan Scams',
  crypto_scams: 'Crypto Scams',
  account_takeover: 'Account Takeover',
  malware_delivery: 'Malware Delivery',
  malicious_downloads: 'Malicious Downloads',
  qr_scams: 'QR Scams',
};

export function normalizeCategory(category: string): RuleCategory | null {
  const normalized = category.trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (ALL_RULE_CATEGORIES.includes(normalized as RuleCategory)) {
    return normalized as RuleCategory;
  }
  // Alternate aliases mapping
  const aliasMap: Record<string, RuleCategory> = {
    phish: 'phishing',
    financial: 'financial_fraud',
    payment: 'payment_fraud',
    credentials: 'credential_theft',
    credential: 'credential_theft',
    otp: 'otp_theft',
    two_factor: 'otp_theft',
    social: 'social_engineering',
    engineering: 'social_engineering',
    job: 'fake_employment',
    employment: 'fake_employment',
    fake_job: 'fake_employment',
    investment: 'fake_investment',
    shopping: 'fake_shopping',
    delivery: 'fake_delivery',
    shipping: 'fake_delivery',
    support: 'fake_support',
    tech_support: 'fake_support',
    romance: 'romance_scams',
    pig_butchering: 'romance_scams',
    giveaway: 'giveaway_scams',
    lottery: 'giveaway_scams',
    loan: 'loan_scams',
    loans: 'loan_scams',
    crypto: 'crypto_scams',
    cryptocurrency: 'crypto_scams',
    ato: 'account_takeover',
    malware: 'malware_delivery',
    download: 'malicious_downloads',
    downloads: 'malicious_downloads',
    qr: 'qr_scams',
    quishing: 'qr_scams',
  };
  return aliasMap[normalized] || null;
}

export type RuleSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface RuleEvaluationContext {
  text: string;
  normalizedText?: string;
  url?: string;
  normalizedUrl?: string;
  qr?: string;
  language?: string;
  metadata?: Record<string, any>;
}

export interface RuleEvidence {
  ruleId: string;
  category: RuleCategory;
  description: string;
  severity: RuleSeverity;
  confidenceContribution: number;
  matchedPatterns: string[];
  snippets: string[];
  context?: Record<string, any>;
}

export interface RuleDetectionResult {
  matched: boolean;
  confidence: number; // 0 - 100
  evidence?: RuleEvidence;
}

export interface RuleTestCase {
  name: string;
  input: {
    text?: string;
    url?: string;
    qr?: string;
    metadata?: Record<string, any>;
  };
  expectedMatch: boolean;
  minConfidence?: number;
}

export interface IScamRule {
  id: string;
  category: RuleCategory;
  description: string;
  severity: RuleSeverity;
  version: string;
  enabled: boolean;
  confidenceContribution: number;
  tags?: string[];
  testCases?: RuleTestCase[];
  detect(context: RuleEvaluationContext): Promise<RuleDetectionResult> | RuleDetectionResult;
  explain?(result: RuleDetectionResult): string;
}

export interface RuleMetrics {
  ruleId: string;
  category: RuleCategory;
  version: string;
  evaluationsCount: number;
  matchCount: number;
  falsePositivesCount: number;
  falseNegativesCount: number;
  totalExecutionTimeMs: number;
  avgExecutionTimeMs: number;
  lastEvaluatedAt?: Date;
  lastMatchedAt?: Date;
  precision: number; // 0 - 100%
}

export interface RuleTestCaseResult {
  testName: string;
  passed: boolean;
  expectedMatch: boolean;
  actualMatch: boolean;
  actualConfidence: number;
  error?: string;
}

export interface RuleTestReport {
  ruleId: string;
  version: string;
  passed: boolean;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  results: RuleTestCaseResult[];
  durationMs: number;
}

export interface FeedbackSubmission {
  ruleId: string;
  type: 'false_positive' | 'false_negative';
  sampleContent: string;
  reason?: string;
  reportedBy?: string;
  timestamp?: Date;
}

export interface FeedbackRecord extends FeedbackSubmission {
  id: string;
  createdAt: Date;
}

export interface MultiSignalScamVerdict {
  isScam: boolean;
  threatLevel: 'CLEAN' | 'LOW' | 'SUSPICIOUS' | 'MALICIOUS';
  scamScore: number; // 0 - 100
  confidence: number; // 0 - 100
  triggeredRules: RuleEvidence[];
  categoriesDetected: RuleCategory[];
  categoryCount: number;
  primaryCategory?: RuleCategory;
  isSingleWeakRule: boolean;
  explanation: string;
  signalsBreakdown: {
    weakCount: number;
    mediumCount: number;
    strongCount: number;
    criticalCount: number;
    correlationMultiplier: number;
  };
  evaluationTimeMs: number;
}
