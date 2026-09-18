export type ScamCategory =
  | 'phishing'
  | 'fake_banking'
  | 'fake_payment'
  | 'fake_job'
  | 'fake_investment'
  | 'fake_shopping'
  | 'fake_delivery'
  | 'fake_prize'
  | 'fake_loan'
  | 'romance_scam'
  | 'impersonation'
  | 'account_takeover'
  | 'otp_theft'
  | 'credential_theft'
  | 'malicious_download'
  | 'qr_scam';

export type LegitimateCategory =
  | 'bank_message'
  | 'delivery_message'
  | 'job_advertisement'
  | 'shopping_website'
  | 'payment_instructions'
  | 'customer_support'
  | 'government_announcement'
  | 'promotional_message'
  | 'investment_information'
  | 'social_media_message';

export type SampleLanguage = 'en' | 'km' | 'km-en';

export type NuanceTag =
  | 'misspellings'
  | 'slang_shorthand'
  | 'shortened_url'
  | 'legitimate_shortener'
  | 'long_url'
  | 'unusual_domain'
  | 'high_urgency'
  | 'polite_neutral'
  | 'mixed_script'
  | 'informational';

export type DifficultyLevel = 'obvious' | 'subtle' | 'adversarial';

export interface EvaluationSample {
  id: string;
  content: string;
  targetType: 'TEXT' | 'URL' | 'QR';
  expectedLabel: 'SCAM' | 'LEGITIMATE';
  category: ScamCategory | LegitimateCategory | string;
  language: SampleLanguage;
  nuanceTags: NuanceTag[];
  difficulty: DifficultyLevel;
  description: string;
  extractedUrls?: string[];
}

export interface SampleEvaluationResult {
  sampleId: string;
  targetType: string;
  expectedLabel: 'SCAM' | 'LEGITIMATE';
  predictedLabel: 'SCAM' | 'LEGITIMATE';
  rawRiskLevel: string;
  score: number;
  confidence: number;
  latencyMs: number;
  isCorrect: boolean;
  isFalsePositive: boolean;
  isFalseNegative: boolean;
  category: string;
  language: SampleLanguage;
  difficulty: DifficultyLevel;
  nuanceTags: NuanceTag[];
  indicators: string[];
}

export interface ConfusionMatrix {
  truePositives: number; // Correctly identified scams
  trueNegatives: number; // Correctly identified legitimate
  falsePositives: number; // Legitimate incorrectly flagged as scam
  falseNegatives: number; // Scam incorrectly classified as legitimate (SECURITY-CRITICAL)
}

export interface LatencyStats {
  meanMs: number;
  medianMs: number;
  p90Ms: number;
  p95Ms: number;
  p99Ms: number;
  minMs: number;
  maxMs: number;
}

export interface PerformanceMetrics {
  total: number;
  confusionMatrix: ConfusionMatrix;
  accuracy: number; // percentage (0 - 100)
  precision: number; // percentage (0 - 100)
  recall: number; // percentage (0 - 100)
  f1Score: number; // percentage (0 - 100)
  falsePositiveRate: number; // percentage (0 - 100)
  falseNegativeRate: number; // percentage (0 - 100)
}

export interface ComprehensiveEvaluationReport extends PerformanceMetrics {
  timestamp: string;
  durationMs: number;
  latency: LatencyStats;
  languageBreakdown: Record<SampleLanguage, PerformanceMetrics>;
  categoryBreakdown: Record<string, PerformanceMetrics>;
  difficultyBreakdown: Record<DifficultyLevel, PerformanceMetrics>;
  nuanceBreakdown: Record<string, PerformanceMetrics>;
  securityAudit: {
    criticalFalseNegativesCount: number;
    flaggedThreatsSampleIds: string[];
    passedSecurityGate: boolean;
    gateFailures: string[];
  };
  sampleResults: SampleEvaluationResult[];
}
