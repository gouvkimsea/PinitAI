export type ScamCategory =
  | 'phishing'
  | 'fake_investment'
  | 'fake_job'
  | 'romance_scam'
  | 'payment_scam'
  | 'account_takeover'
  | 'impersonation'
  | 'lottery_scam'
  | 'cryptocurrency_scam'
  | 'tech_support_scam';

export const SUPPORTED_SCAM_CATEGORIES: ScamCategory[] = [
  'phishing',
  'fake_investment',
  'fake_job',
  'romance_scam',
  'payment_scam',
  'account_takeover',
  'impersonation',
  'lottery_scam',
  'cryptocurrency_scam',
  'tech_support_scam',
];

export type PatternSeverity = 'low' | 'medium' | 'high' | 'critical';

export type PatternStatus = 'active' | 'inactive' | 'pending_review' | 'deprecated';

export interface ScamPatternRecord {
  id: string;
  pattern: string;
  category: ScamCategory | string;
  severity: PatternSeverity;
  description: string;
  source: string;
  status: PatternStatus;
  createdAt: string | Date;
  updatedAt: string | Date;
}

export interface CreatePatternInput {
  pattern: string;
  category: ScamCategory | string;
  severity: PatternSeverity;
  description: string;
  source: string;
  status?: PatternStatus;
}

export interface UpdatePatternInput {
  pattern?: string;
  category?: ScamCategory | string;
  severity?: PatternSeverity;
  description?: string;
  source?: string;
  status?: PatternStatus;
}

export interface PatternQueryFilter {
  category?: string;
  severity?: PatternSeverity;
  status?: PatternStatus;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface PatternMatch {
  id: string;
  pattern: string;
  category: string;
  severity: PatternSeverity;
  description: string;
  source: string;
  matched_text: string;
  weight: number;
}

export interface ContentComparisonOptions {
  categories?: string[];
  minSeverity?: PatternSeverity;
  includeInactive?: boolean;
  maxMatches?: number;
}

export interface ContentComparisonResult {
  matched: boolean;
  matched_patterns: PatternMatch[];
  categories_detected: string[];
  highest_severity: PatternSeverity | 'safe';
  scam_score: number; // 0 to 100
  recommended_action: string;
  evaluated_pattern_count: number;
  execution_time_ms: number;
}
