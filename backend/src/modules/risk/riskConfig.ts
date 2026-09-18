import { RiskAssessmentState } from './types';

export type RiskClassification =
  | 'Low Risk'
  | 'Mild Risk'
  | 'Suspicious'
  | 'High Risk'
  | 'Critical Risk'
  | 'Needs Review'
  | 'Insufficient Evidence';

export interface RiskScoringWeights {
  textAnalysis: number;
  urlAnalysis: number;
  domainReputation: number;
  scamPatterns: number;
  impersonation: number;
  fileAnalysis: number;
  communityReports: number;
  aiAnalysis: number;
}

export interface CriticalSecurityRuleDefinition {
  id: string;
  name: string;
  detectorName: string;
  minScore: number;
  description: string;
}

export interface CriticalSecurityRuleConfig {
  allowCriticalOverrides: boolean;
  criticalThreshold: number;
  rules: CriticalSecurityRuleDefinition[];
}

export interface RiskThresholdsConfig {
  lowRiskMax: number;       // 25 -> safe / low risk
  mildRiskMax: number;      // 40
  suspiciousMax: number;    // 60 -> suspicious
  highRiskMax: number;      // 80 -> high risk
  criticalRiskMax: number;  // 100 -> confirmed malicious
  insufficientEvidenceConfidenceMin: number; // 40: below this confidence, flag insufficient evidence
  confirmedMaliciousConfidenceMin: number;   // 70: must have at least this confidence for confirmed malicious
}

export interface RiskEngineConfig {
  weights: RiskScoringWeights;
  criticalRules: CriticalSecurityRuleConfig;
  thresholds: RiskThresholdsConfig;
  correlationBoost: {
    enabled: boolean;
    minTriggeringDetectors: number;
    minScoreThreshold: number;
    boostMultiplier: number;
  };
  deCorrelation: {
    enabled: boolean;
    intraGroupDampeningFactor: number; // factor applied to secondary signals in the same group (default: 0.25)
  };
}

export const DEFAULT_RISK_WEIGHTS: RiskScoringWeights = {
  textAnalysis: 0.15,
  urlAnalysis: 0.20,
  domainReputation: 0.15,
  scamPatterns: 0.20,
  impersonation: 0.15,
  fileAnalysis: 0.25,
  communityReports: 0.15,
  aiAnalysis: 0.10,
};

export const DEFAULT_CRITICAL_SECURITY_RULES: CriticalSecurityRuleDefinition[] = [
  {
    id: 'MALWARE_SIGNATURE_DETECTED',
    name: 'Verified Malware Signature',
    detectorName: 'file_security_detector',
    minScore: 85,
    description: 'Antivirus or hash check confirmed known malicious payload/trojan.',
  },
  {
    id: 'MAGIC_BYTES_EXECUTABLE_MISMATCH',
    name: 'Deceptive Executable Disguise',
    detectorName: 'file_security_detector',
    minScore: 70,
    description: 'File magic bytes confirm DOS/PE executable masquerading as a harmless format.',
  },
  {
    id: 'ACTIVE_SSRF_PROBE',
    name: 'Private Network SSRF Probe',
    detectorName: 'url_security_detector',
    minScore: 90,
    description: 'Target URL attempts to probe loopback, RFC1918 private network, or cloud metadata.',
  },
  {
    id: 'VERIFIED_PHISHING_DOMAIN',
    name: 'Active Phishing Threat Feed Listing',
    detectorName: 'reputation_signal_detector',
    minScore: 85,
    description: 'Domain is actively listed on verified zero-tolerance phishing blocklists.',
  },
];

export const DEFAULT_RISK_CONFIG: RiskEngineConfig = {
  weights: { ...DEFAULT_RISK_WEIGHTS },
  criticalRules: {
    allowCriticalOverrides: true,
    criticalThreshold: 85,
    rules: [...DEFAULT_CRITICAL_SECURITY_RULES],
  },
  thresholds: {
    lowRiskMax: 20,
    mildRiskMax: 40,
    suspiciousMax: 60,
    highRiskMax: 80,
    criticalRiskMax: 100,
    insufficientEvidenceConfidenceMin: 40,
    confirmedMaliciousConfidenceMin: 70,
  },
  correlationBoost: {
    enabled: true,
    minTriggeringDetectors: 2,
    minScoreThreshold: 35,
    boostMultiplier: 1.25,
  },
  deCorrelation: {
    enabled: true,
    intraGroupDampeningFactor: 0.25,
  },
};

export class RiskConfigManager {
  private currentConfig: RiskEngineConfig;

  constructor(initialConfig?: Partial<RiskEngineConfig>) {
    this.currentConfig = this.deepClone({
      ...DEFAULT_RISK_CONFIG,
      ...initialConfig,
    });
  }

  getConfig(): RiskEngineConfig {
    return this.deepClone(this.currentConfig);
  }

  updateConfig(updates: Partial<RiskEngineConfig>): RiskEngineConfig {
    if (updates.weights) {
      this.currentConfig.weights = {
        ...this.currentConfig.weights,
        ...updates.weights,
      };
    }
    if (updates.criticalRules) {
      this.currentConfig.criticalRules = {
        ...this.currentConfig.criticalRules,
        ...updates.criticalRules,
      };
    }
    if (updates.thresholds) {
      this.currentConfig.thresholds = {
        ...this.currentConfig.thresholds,
        ...updates.thresholds,
      };
    }
    if (updates.correlationBoost) {
      this.currentConfig.correlationBoost = {
        ...this.currentConfig.correlationBoost,
        ...updates.correlationBoost,
      };
    }
    if (updates.deCorrelation) {
      this.currentConfig.deCorrelation = {
        ...this.currentConfig.deCorrelation,
        ...updates.deCorrelation,
      };
    }
    return this.getConfig();
  }

  resetConfig(): RiskEngineConfig {
    this.currentConfig = this.deepClone(DEFAULT_RISK_CONFIG);
    return this.getConfig();
  }

  /**
   * Evaluates 2D (Risk vs. Confidence) orthogonal state:
   * - SAFE_LOW_RISK
   * - SUSPICIOUS
   * - HIGH_RISK
   * - CONFIRMED_MALICIOUS
   * - INSUFFICIENT_EVIDENCE
   */
  classifyState(riskScore: number, confidenceScore: number): RiskAssessmentState {
    const { thresholds } = this.currentConfig;
    const clampedRisk = Math.max(0, Math.min(100, Math.round(riskScore)));
    const clampedConf = Math.max(0, Math.min(100, Math.round(confidenceScore)));

    // If confidence is below the minimum threshold and risk is not overwhelming
    if (clampedConf < thresholds.insufficientEvidenceConfidenceMin) {
      return 'INSUFFICIENT_EVIDENCE';
    }

    // High risk with high confidence confirms malicious threat
    if (clampedRisk >= thresholds.highRiskMax && clampedConf >= thresholds.confirmedMaliciousConfidenceMin) {
      return 'CONFIRMED_MALICIOUS';
    }

    // High risk with moderate confidence
    if (clampedRisk >= thresholds.suspiciousMax) {
      return 'HIGH_RISK';
    }

    // Suspicious risk
    if (clampedRisk > thresholds.lowRiskMax) {
      return 'SUSPICIOUS';
    }

    // Safe / low risk
    return 'SAFE_LOW_RISK';
  }

  classifyScore(score: number): RiskClassification {
    const clamped = Math.max(0, Math.min(100, Math.round(score)));
    const { lowRiskMax, mildRiskMax, suspiciousMax, highRiskMax } = this.currentConfig.thresholds;

    if (clamped <= lowRiskMax) return 'Low Risk';
    if (clamped <= mildRiskMax) return 'Mild Risk';
    if (clamped <= suspiciousMax) return 'Suspicious';
    if (clamped <= highRiskMax) return 'High Risk';
    return 'Critical Risk';
  }

  getRecommendedAction(classification: RiskClassification | RiskAssessmentState): string {
    switch (classification) {
      case 'CONFIRMED_MALICIOUS':
      case 'Critical Risk':
        return 'IMMEDIATE ACTION REQUIRED: High-confidence malicious threat detected. Do not open, click, or engage with this content. Block sender immediately and report to cybersecurity incident responders.';
      case 'HIGH_RISK':
      case 'High Risk':
        return 'WARNING: Significant deception or scam patterns identified. Do not disclose personal or financial credentials. Verify the source independently through trusted official channels.';
      case 'SUSPICIOUS':
      case 'Suspicious':
        return 'CAUTION: Anomalous or unverified indicators detected. Exercise heightened vigilance. Refrain from clicking embedded links or executing attachments until independently confirmed.';
      case 'Mild Risk':
        return 'NOTE: Mild irregularities or promotional urgency detected. Content is likely safe but warrants standard digital safety precautions.';
      case 'INSUFFICIENT_EVIDENCE':
      case 'Insufficient Evidence':
      case 'Needs Review':
        return 'INSUFFICIENT EVIDENCE: Assessment confidence is limited due to sparse or uncorroborated indicators. Treat as potentially dangerous until additional verification can be completed.';
      case 'SAFE_LOW_RISK':
      case 'Low Risk':
      default:
        return 'CLEAN: Strong evidence that no significant scam indicators exist. Standard online awareness is always recommended.';
    }
  }

  private deepClone<T>(obj: T): T {
    return JSON.parse(JSON.stringify(obj));
  }
}

export const riskConfigManager = new RiskConfigManager();
