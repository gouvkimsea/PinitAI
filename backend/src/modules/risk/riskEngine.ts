import { ThreatLevel } from '../../types';
import { EvidenceCollection } from '../../pipeline/types';
import {
  RiskClassification,
  RiskEngineConfig,
  riskConfigManager,
} from './riskConfig';

export interface EvidenceWeights {
  messageScore?: number;
  urlScore?: number;
  indicatorsScore?: number;
  reputationScore?: number;
  behaviorScore?: number;
  patternScore?: number;
  impersonationScore?: number;
  fileScore?: number;
  communityScore?: number;
}

export interface RiskCalculationResult {
  // Primary structured fields required by Centralized Risk Engine
  risk_score: number;
  classification: RiskClassification;
  confidence: number;
  triggered_detectors: string[];
  evidence: {
    summary: string;
    indicators: string[];
    breakdown: Record<string, number>;
    criticalRulesTriggered: string[];
  };
  recommended_action: string;

  // Backward-compatible camelCase properties for existing services & tests
  riskScore: number;
  threatLevel: ThreatLevel;
  confidenceScore: number;
  evidenceBreakdown: {
    messageAnalysisScore: number;
    urlAnalysisScore: number;
    threatIndicatorsScore: number;
    reputationScore: number;
    behavioralScore: number;
    patternScore: number;
    impersonationScore: number;
    communityScore: number;
    fileScore: number;
    aiScore: number;
  };
}

export class RiskEngine {
  private configManager = riskConfigManager;

  /**
   * Retrieves the current risk scoring configuration
   */
  getConfig(): RiskEngineConfig {
    return this.configManager.getConfig();
  }

  /**
   * Dynamically updates risk scoring configuration (weights, thresholds, critical rules)
   * without requiring application rewrites or restarts.
   */
  updateConfig(updates: Partial<RiskEngineConfig>): RiskEngineConfig {
    return this.configManager.updateConfig(updates);
  }

  /**
   * Resets configuration to factory defaults
   */
  resetConfig(): RiskEngineConfig {
    return this.configManager.resetConfig();
  }

  /**
   * Evaluates an EvidenceCollection combining the 7 core detection signals:
   * 1. Text analysis
   * 2. URL analysis
   * 3. Domain reputation
   * 4. Scam patterns
   * 5. Impersonation detection
   * 6. File analysis
   * 7. Community/user reports
   * (Plus AI model contextual embeddings as an additional signal)
   *
   * Enforces the anti-unilateral rule: no single detector can dictate the final score
   * unless it triggers an explicitly configured critical security rule.
   */
  evaluateEvidence(collection: EvidenceCollection): RiskCalculationResult {
    const config = this.configManager.getConfig();
    const weights = config.weights;

    let textScore = 0;
    let urlScore = 0;
    let reputationScore = 0;
    let patternScore = 0;
    let impersonationScore = 0;
    let fileScore = 0;
    let communityScore = 0;
    let aiScore = 0;

    let hasText = false;
    let hasUrl = false;
    let hasReputation = false;
    let hasPattern = false;
    let hasImpersonation = false;
    let hasFile = false;
    let hasCommunity = false;
    let hasAi = false;

    const triggeredDetectors: string[] = [];
    const criticalRulesTriggered: string[] = [];

    // 1. Process individual detector findings
    for (const res of collection.detectorResults) {
      if (res.score > 0) {
        triggeredDetectors.push(res.detector_name);
      }

      switch (res.detector_type) {
        case 'text':
          textScore = Math.max(textScore, res.score);
          hasText = true;
          break;
        case 'url':
          urlScore = Math.max(urlScore, res.score);
          hasUrl = true;
          break;
        case 'reputation':
          reputationScore = Math.max(reputationScore, res.score);
          hasReputation = true;
          break;
        case 'pattern':
          patternScore = Math.max(patternScore, res.score);
          hasPattern = true;
          break;
        case 'impersonation':
          impersonationScore = Math.max(impersonationScore, res.score);
          hasImpersonation = true;
          break;
        case 'file':
          fileScore = Math.max(fileScore, res.score);
          hasFile = true;
          break;
        case 'community':
          communityScore = Math.max(communityScore, res.score);
          hasCommunity = true;
          break;
        case 'ai':
          aiScore = Math.max(aiScore, res.score);
          hasAi = true;
          break;
      }

      // Check if this detector triggered an explicitly configured critical security rule
      if (config.criticalRules.allowCriticalOverrides) {
        for (const rule of config.criticalRules.rules) {
          if (res.detector_name === rule.detectorName && res.score >= rule.minScore) {
            criticalRulesTriggered.push(rule.id);
          }
        }
      }
    }

    // 2. Dynamically redistribute weights across actively evaluated signal categories
    let wText = hasText ? weights.textAnalysis : 0;
    let wUrl = hasUrl ? weights.urlAnalysis : 0;
    let wRep = hasReputation ? weights.domainReputation : 0;
    let wPattern = hasPattern ? weights.scamPatterns : 0;
    let wImp = hasImpersonation ? weights.impersonation : 0;
    let wFile = hasFile ? weights.fileAnalysis : 0;
    let wComm = hasCommunity ? weights.communityReports : 0;
    let wAi = hasAi ? weights.aiAnalysis : 0;

    const totalActiveWeight = wText + wUrl + wRep + wPattern + wImp + wFile + wComm + wAi;
    if (totalActiveWeight > 0) {
      wText /= totalActiveWeight;
      wUrl /= totalActiveWeight;
      wRep /= totalActiveWeight;
      wPattern /= totalActiveWeight;
      wImp /= totalActiveWeight;
      wFile /= totalActiveWeight;
      wComm /= totalActiveWeight;
      wAi /= totalActiveWeight;
    }

    // 3. Compute base weighted score
    let rawWeightedScore =
      textScore * wText +
      urlScore * wUrl +
      reputationScore * wRep +
      patternScore * wPattern +
      impersonationScore * wImp +
      fileScore * wFile +
      communityScore * wComm +
      aiScore * wAi;

    // 4. Evaluate Critical Security Rule Overrides vs Anti-Unilateral Rule
    // "Do not allow one detector to automatically determine the final result unless explicitly configured as a critical security rule."
    const hasCriticalOverride = criticalRulesTriggered.length > 0;
    const maxIndividualScore = Math.max(
      textScore,
      urlScore,
      reputationScore,
      patternScore,
      impersonationScore,
      fileScore,
      communityScore,
      aiScore
    );

    let finalScore = rawWeightedScore;

    if (hasCriticalOverride) {
      // Explicit critical security rule triggered: apply critical security floor
      const criticalFloor = config.criticalRules.criticalThreshold;
      finalScore = Math.max(finalScore, criticalFloor);
    } else {
      // No critical security rule triggered:
      // Single detectors CANNOT dictate the final score alone.
      // However, if multiple independent detectors concur, apply correlation boosting.
      const triggeringDetectors = collection.detectorResults.filter(
        (r) => r.score >= config.correlationBoost.minScoreThreshold
      );

      if (
        config.correlationBoost.enabled &&
        triggeringDetectors.length >= config.correlationBoost.minTriggeringDetectors
      ) {
        // Multi-detector consensus detected: boost the weighted score to reflect confirmed agreement
        const boosted = rawWeightedScore * config.correlationBoost.boostMultiplier;
        finalScore = Math.min(100, Math.max(boosted, maxIndividualScore));
      } else {
        // Only 1 detector triggered (or multiple below threshold):
        // Anti-unilateral rule: strictly retain the weighted score without unilateral override!
        finalScore = rawWeightedScore;
      }
    }

    const normalizedRiskScore = Math.min(100, Math.max(0, Math.round(finalScore)));
    const classification = this.configManager.classifyScore(normalizedRiskScore);

    // Map to legacy ThreatLevel
    let threatLevel: ThreatLevel = 'SAFE';
    switch (classification) {
      case 'Critical Risk':
        threatLevel = 'MALICIOUS';
        break;
      case 'High Risk':
        threatLevel = 'HIGH_RISK';
        break;
      case 'Suspicious':
        threatLevel = 'SUSPICIOUS';
        break;
      case 'Mild Risk':
        threatLevel = 'LOW_RISK';
        break;
      case 'Low Risk':
      default:
        threatLevel = 'SAFE';
        break;
    }

    // 5. Calculate Confidence Score (0–100)
    let confidence = 50;
    if (collection.totalDetectorsRan >= 3) confidence += 15;
    if (collection.indicators.length > 0) confidence += 15;
    if (triggeredDetectors.length >= 2) confidence += 15;
    if (hasCriticalOverride) confidence = Math.max(confidence, 95);
    confidence = Math.min(99, Math.max(40, confidence));

    // 6. Formulate Recommended Action & Structured Evidence
    const recommendedAction = this.configManager.getRecommendedAction(classification);

    const evidenceBreakdown = {
      messageAnalysisScore: Math.round(textScore),
      urlAnalysisScore: Math.round(urlScore),
      threatIndicatorsScore: Math.round(patternScore),
      reputationScore: Math.round(reputationScore),
      behavioralScore: Math.round(fileScore || aiScore),
      patternScore: Math.round(patternScore),
      impersonationScore: Math.round(impersonationScore),
      communityScore: Math.round(communityScore),
      fileScore: Math.round(fileScore),
      aiScore: Math.round(aiScore),
    };

    const evidenceSummary =
      collection.indicators.length > 0
        ? `Identified ${collection.indicators.length} threat indicators across ${triggeredDetectors.length} active detection signals.`
        : 'No malicious or suspicious indicators detected across evaluated signals.';

    return {
      risk_score: normalizedRiskScore,
      classification,
      confidence,
      triggered_detectors: triggeredDetectors,
      evidence: {
        summary: evidenceSummary,
        indicators: collection.indicators,
        breakdown: evidenceBreakdown,
        criticalRulesTriggered,
      },
      recommended_action: recommendedAction,

      // Backward-compatible properties
      riskScore: normalizedRiskScore,
      threatLevel,
      confidenceScore: confidence,
      evidenceBreakdown,
    };
  }

  /**
   * Calculates normalized 0-100 composite risk score using EvidenceWeights (Legacy interface)
   */
  calculateRisk(weightsInput: EvidenceWeights): RiskCalculationResult {
    const config = this.configManager.getConfig();
    const w = config.weights;

    const hasMsg = weightsInput.messageScore !== undefined;
    const hasUrl = weightsInput.urlScore !== undefined;
    const hasInd = weightsInput.indicatorsScore !== undefined;
    const hasRep = weightsInput.reputationScore !== undefined;
    const hasBeh = weightsInput.behaviorScore !== undefined;
    const hasPat = weightsInput.patternScore !== undefined;
    const hasImp = weightsInput.impersonationScore !== undefined;
    const hasFile = weightsInput.fileScore !== undefined;
    const hasComm = weightsInput.communityScore !== undefined;

    let wMsg = hasMsg ? w.textAnalysis : 0;
    let wUrl = hasUrl ? w.urlAnalysis : 0;
    let wInd = hasInd ? w.scamPatterns : 0;
    let wRep = hasRep ? w.domainReputation : 0;
    let wBeh = hasBeh ? w.aiAnalysis : 0;
    let wPat = hasPat ? w.scamPatterns : 0;
    let wImp = hasImp ? w.impersonation : 0;
    let wFile = hasFile ? w.fileAnalysis : 0;
    let wComm = hasComm ? w.communityReports : 0;

    const totalWeight = wMsg + wUrl + wInd + wRep + wBeh + wPat + wImp + wFile + wComm;
    if (totalWeight > 0) {
      wMsg /= totalWeight;
      wUrl /= totalWeight;
      wInd /= totalWeight;
      wRep /= totalWeight;
      wBeh /= totalWeight;
      wPat /= totalWeight;
      wImp /= totalWeight;
      wFile /= totalWeight;
      wComm /= totalWeight;
    }

    const msgVal = weightsInput.messageScore || 0;
    const urlVal = weightsInput.urlScore || 0;
    const indVal = weightsInput.indicatorsScore || 0;
    const repVal = weightsInput.reputationScore || 0;
    const behVal = weightsInput.behaviorScore || 0;
    const patVal = weightsInput.patternScore || 0;
    const impVal = weightsInput.impersonationScore || 0;
    const fileVal = weightsInput.fileScore || 0;
    const commVal = weightsInput.communityScore || 0;

    const rawScore =
      msgVal * wMsg +
      urlVal * wUrl +
      indVal * wInd +
      repVal * wRep +
      behVal * wBeh +
      patVal * wPat +
      impVal * wImp +
      fileVal * wFile +
      commVal * wComm;

    const finalScore = Math.min(100, Math.max(0, Math.round(rawScore)));
    const classification = this.configManager.classifyScore(finalScore);

    let threatLevel: ThreatLevel = 'SAFE';
    switch (classification) {
      case 'Critical Risk':
        threatLevel = 'MALICIOUS';
        break;
      case 'High Risk':
        threatLevel = 'HIGH_RISK';
        break;
      case 'Suspicious':
        threatLevel = 'SUSPICIOUS';
        break;
      case 'Mild Risk':
        threatLevel = 'LOW_RISK';
        break;
      case 'Low Risk':
      default:
        threatLevel = 'SAFE';
        break;
    }

    const triggered: string[] = [];
    if (msgVal > 0) triggered.push('text_analysis');
    if (urlVal > 0) triggered.push('url_analysis');
    if (patVal > 0 || indVal > 0) triggered.push('scam_patterns');
    if (repVal > 0) triggered.push('domain_reputation');
    if (impVal > 0) triggered.push('impersonation_detection');
    if (fileVal > 0) triggered.push('file_analysis');
    if (commVal > 0) triggered.push('community_reports');
    if (behVal > 0) triggered.push('ai_analysis');

    let confidence = 50;
    if (indVal > 0 || patVal > 0) confidence += 15;
    if (msgVal > 50 || urlVal > 50) confidence += 15;
    if (repVal > 0 || behVal > 0) confidence += 10;
    confidence = Math.min(99, Math.max(40, confidence));

    const recommendedAction = this.configManager.getRecommendedAction(classification);

    const breakdown = {
      messageAnalysisScore: Math.round(msgVal),
      urlAnalysisScore: Math.round(urlVal),
      threatIndicatorsScore: Math.round(indVal || patVal),
      reputationScore: Math.round(repVal),
      behavioralScore: Math.round(behVal),
      patternScore: Math.round(patVal),
      impersonationScore: Math.round(impVal),
      communityScore: Math.round(commVal),
      fileScore: Math.round(fileVal),
      aiScore: Math.round(behVal),
    };

    return {
      risk_score: finalScore,
      classification,
      confidence,
      triggered_detectors: triggered,
      evidence: {
        summary: `Computed weighted score from ${triggered.length} active signal categories.`,
        indicators: [],
        breakdown,
        criticalRulesTriggered: [],
      },
      recommended_action: recommendedAction,

      riskScore: finalScore,
      threatLevel,
      confidenceScore: confidence,
      evidenceBreakdown: breakdown,
    };
  }
}

export const riskEngine = new RiskEngine();
