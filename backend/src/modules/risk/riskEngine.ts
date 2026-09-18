import { ThreatLevel } from '../../types';
import { EvidenceCollection } from '../../pipeline/types';
import {
  RiskClassification,
  RiskEngineConfig,
  riskConfigManager,
} from './riskConfig';
import {
  EvidenceSignal,
  RiskAssessmentState,
  SignalCorrelationGroup,
  SignalSeverity,
} from './types';

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
  state: RiskAssessmentState;
  triggered_detectors: string[];
  evidence: {
    summary: string;
    indicators: string[];
    breakdown: Record<string, number>;
    criticalRulesTriggered: string[];
  };
  recommended_action: string;

  // Signal & correlation transparency
  signals: EvidenceSignal[];
  de_correlated_signals: EvidenceSignal[];
  correlation_groups: Record<string, SignalCorrelationGroup>;

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

  getConfig(): RiskEngineConfig {
    return this.configManager.getConfig();
  }

  updateConfig(updates: Partial<RiskEngineConfig>): RiskEngineConfig {
    return this.configManager.updateConfig(updates);
  }

  resetConfig(): RiskEngineConfig {
    return this.configManager.resetConfig();
  }

  /**
   * Intrinsic reliability ratings by detector source
   */
  private getSourceReliability(source: string): number {
    switch (source) {
      case 'file_security_detector':
        return 0.95; // High deterministic accuracy (AV hashes, magic bytes)
      case 'reputation_signal_detector':
        return 0.90; // Threat feeds & blocklists
      case 'impersonation_detector':
        return 0.85; // Curated brand dictionary & combisquatting
      case 'scam_pattern_detector':
        return 0.80; // Validated regex & threat intelligence
      case 'url_security_detector':
        return 0.80; // Structural, IP, redirect probes
      case 'text_linguistic_detector':
        return 0.70; // Natural language heuristics
      case 'community_intelligence_detector':
        return 0.75; // Crowdsourced consensus
      case 'ai_model_detector':
        return 0.65; // Machine learning probability
      default:
        return 0.60;
    }
  }

  /**
   * Derives a correlation group key for a signal to prevent double-counting.
   * Multiple features sharing the same underlying origin or domain characteristic
   * are assigned to the same correlation group.
   */
  private deriveCorrelationGroup(source: string, indicator: string): string {
    const lower = indicator.toLowerCase();

    // Domain & URL syntactic characteristics
    if (
      lower.includes('domain') ||
      lower.includes('tld') ||
      lower.includes('combisquatting') ||
      lower.includes('typosquatting') ||
      lower.includes('hostname') ||
      lower.includes('entropy') ||
      lower.includes('subdomain') ||
      lower.includes('hyphen') ||
      lower.includes('ip address') ||
      lower.includes('redirect')
    ) {
      return 'url:domain_structure';
    }

    // Urgency and social engineering tone
    if (
      lower.includes('urgency') ||
      lower.includes('coercive') ||
      lower.includes('fear') ||
      lower.includes('threat of arrest') ||
      lower.includes('pressure')
    ) {
      return 'linguistic:urgency';
    }

    // Financial lure / prize / giveaway patterns
    if (
      lower.includes('lottery') ||
      lower.includes('prize') ||
      lower.includes('giveaway') ||
      lower.includes('crypto') ||
      lower.includes('doubling') ||
      lower.includes('investment') ||
      lower.includes('profit')
    ) {
      return 'pattern:financial_lure';
    }

    // Credential harvesting / banking authentication
    if (
      lower.includes('credential') ||
      lower.includes('login') ||
      lower.includes('account frozen') ||
      lower.includes('verify your account') ||
      lower.includes('otp')
    ) {
      return 'pattern:credential_harvesting';
    }

    // Binary / Executable payloads
    if (
      lower.includes('trojan') ||
      lower.includes('malware') ||
      lower.includes('executable') ||
      lower.includes('magic bytes') ||
      lower.includes('pe header')
    ) {
      return 'payload:binary_threat';
    }

    return `${source}:general`;
  }

  /**
   * Extracts and standardizes EvidenceSignals containing all 7 required properties:
   * source, signalType, severity, reliability, confidence, timestamp, explanation.
   */
  public extractSignals(collection: EvidenceCollection): EvidenceSignal[] {
    const now = new Date().toISOString();
    const signals: EvidenceSignal[] = [];

    for (const res of collection.detectorResults) {
      if (res.score <= 0 && (!res.evidence.indicators || res.evidence.indicators.length === 0)) {
        continue;
      }

      const source = res.detector_name;
      const reliability = this.getSourceReliability(source);
      const detectorConfidence = Math.max(0, Math.min(100, res.confidence || 70));

      if (res.evidence.indicators && res.evidence.indicators.length > 0) {
        for (let i = 0; i < res.evidence.indicators.length; i++) {
          const ind = res.evidence.indicators[i];
          const correlationGroup = this.deriveCorrelationGroup(source, ind);
          const severity: SignalSeverity =
            res.severity === 'critical'
              ? 'critical'
              : res.severity === 'high'
              ? 'high'
              : res.severity === 'medium'
              ? 'medium'
              : res.severity === 'low'
              ? 'low'
              : 'safe';

          signals.push({
            id: `${source}-sig-${i + 1}-${Date.now().toString(36)}`,
            source,
            signalType: res.detector_type,
            severity,
            reliability,
            confidence: detectorConfidence,
            timestamp: now,
            explanation: ind,
            score: res.score,
            correlationGroup,
            rawDetails: res.evidence.details,
          });
        }
      } else if (res.score > 0) {
        const correlationGroup = this.deriveCorrelationGroup(source, res.evidence.summary);
        signals.push({
          id: `${source}-summary-${Date.now().toString(36)}`,
          source,
          signalType: res.detector_type,
          severity: res.severity,
          reliability,
          confidence: detectorConfidence,
          timestamp: now,
          explanation: res.evidence.summary,
          score: res.score,
          correlationGroup,
          rawDetails: res.evidence.details,
        });
      }
    }

    return signals;
  }

  /**
   * De-correlates signals to prevent double-counting correlated indicators.
   * E.g. Five URL features derived from the same domain structure are grouped,
   * with the primary signal contributing at 100% and secondary signals dampened
   * by the configured intraGroupDampeningFactor (default 0.25).
   */
  public deCorrelateSignals(signals: EvidenceSignal[]): {
    deCorrelatedSignals: EvidenceSignal[];
    groups: Record<string, SignalCorrelationGroup>;
  } {
    const config = this.configManager.getConfig();
    const dampeningFactor = config.deCorrelation.enabled
      ? config.deCorrelation.intraGroupDampeningFactor
      : 1.0;

    const groupMap: Record<string, EvidenceSignal[]> = {};
    for (const sig of signals) {
      const g = sig.correlationGroup || `${sig.source}:general`;
      if (!groupMap[g]) groupMap[g] = [];
      groupMap[g].push(sig);
    }

    const groups: Record<string, SignalCorrelationGroup> = {};
    const deCorrelatedSignals: EvidenceSignal[] = [];

    for (const [groupId, groupSignals] of Object.entries(groupMap)) {
      // Sort signals in group descending by (score * reliability)
      groupSignals.sort((a, b) => {
        const scoreA = (a.score || 0) * a.reliability;
        const scoreB = (b.score || 0) * b.reliability;
        return scoreB - scoreA;
      });

      const primarySignal = groupSignals[0];
      const remainingSignals = groupSignals.slice(1);

      // Dampen remaining signals
      let dampenedExtraScore = 0;
      for (const rem of remainingSignals) {
        dampenedExtraScore += (rem.score || 0) * dampeningFactor;
      }

      const effectiveScore = Math.min(100, Math.round((primarySignal.score || 0) + dampenedExtraScore));

      groups[groupId] = {
        groupId,
        signals: groupSignals,
        primarySignal,
        effectiveScore,
        dampenedScoreContribution: dampenedExtraScore,
      };

      // Add the primary signal and discounted secondary signals
      deCorrelatedSignals.push({
        ...primarySignal,
        score: effectiveScore,
      });
    }

    return { deCorrelatedSignals, groups };
  }

  /**
   * Computes Orthogonal Confidence Score (0 to 100).
   * Separates "How dangerous the evidence appears" from "How confident we are".
   *
   * Factors:
   * - Breadth: Number of detectors evaluated out of potential detectors
   * - Agreement: Consensus among independent detection sources
   * - Signal Reliability: Intrinsic reliability of sources providing evidence
   * - Ambiguity Dampening: Conflicting signals reduce confidence
   * - Critical Rule Overrides: Verified cryptographic/hash matches provide near certainty
   */
  public calculateConfidence(
    collection: EvidenceCollection,
    signals: EvidenceSignal[],
    hasCriticalOverride: boolean,
    distinctDetectorsTriggered: number
  ): number {
    if (hasCriticalOverride) {
      return 95;
    }

    // Base confidence starts from detector coverage
    const detectorsRan = collection.totalDetectorsRan || 1;
    // Coverage component: 30 to 50 based on detector count (e.g. 3 detectors = 45, 5 detectors = 50)
    let coverageScore = Math.min(50, 30 + detectorsRan * 5);

    // Corroboration component: agreement across distinct sources
    let corroborationBonus = 0;
    if (distinctDetectorsTriggered >= 3) {
      corroborationBonus = 40;
    } else if (distinctDetectorsTriggered === 2) {
      corroborationBonus = 25;
    } else if (distinctDetectorsTriggered === 1) {
      corroborationBonus = 5;
    } else if (collection.cleanCount >= 3) {
      // Multiple detectors ran and all agree it is clean -> high confidence in safety!
      corroborationBonus = 40;
    }

    // Reliability and individual detector confidence of active sources
    let avgReliability = 0.70;
    let avgDetectorConf = 75;
    if (signals.length > 0) {
      const sumRel = signals.reduce((acc, s) => acc + s.reliability, 0);
      avgReliability = sumRel / signals.length;
      const sumConf = signals.reduce((acc, s) => acc + s.confidence, 0);
      avgDetectorConf = sumConf / signals.length;
    } else if (detectorsRan >= 4) {
      avgReliability = 0.85; // clean run across multiple trusted engines
      avgDetectorConf = 85;
    }

    const reliabilityAdjustment = (avgReliability - 0.5) * 15; // -7.5 to +7.5
    const detectorConfAdjustment = (avgDetectorConf - 70) * 0.2; // -4 to +6

    let compositeConfidence = coverageScore + corroborationBonus + reliabilityAdjustment + detectorConfAdjustment;

    // Sparse or uncorroborated single heuristic signal check:
    // If only 1 detector ran or only 1 weak signal triggered with 0 corroboration,
    // confidence must be kept low (< 40) so it triggers INSUFFICIENT_EVIDENCE when appropriate
    if (detectorsRan <= 1 && signals.length <= 1) {
      compositeConfidence = Math.min(35, compositeConfidence);
    }

    return Math.min(99, Math.max(25, Math.round(compositeConfidence)));
  }

  /**
   * Evaluates an EvidenceCollection with full separation of Risk and Confidence.
   */
  evaluateEvidence(collection: EvidenceCollection): RiskCalculationResult {
    const config = this.configManager.getConfig();
    const weights = config.weights;

    // 1. Extract and De-correlate Signals
    const rawSignals = this.extractSignals(collection);
    const { deCorrelatedSignals, groups } = this.deCorrelateSignals(rawSignals);

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

    // Map de-correlated signals back to category scores
    for (const res of collection.detectorResults) {
      if (res.score > 0) {
        triggeredDetectors.push(res.detector_name);
      }

      // Check critical rules
      if (config.criticalRules.allowCriticalOverrides) {
        for (const rule of config.criticalRules.rules) {
          if (res.detector_name === rule.detectorName && res.score >= rule.minScore) {
            criticalRulesTriggered.push(rule.id);
          }
        }
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
    }

    // Apply de-correlated dampening to category scores if multiple correlated signals exist
    // URL & Impersonation correlation dampening check
    const domainGroup = groups['url:domain_structure'];
    if (domainGroup && domainGroup.signals.length > 1) {
      urlScore = Math.min(urlScore, domainGroup.effectiveScore);
    }
    const urgencyGroup = groups['linguistic:urgency'];
    if (urgencyGroup && urgencyGroup.signals.length > 1) {
      textScore = Math.min(textScore, urgencyGroup.effectiveScore);
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

    // 3. Compute base weighted risk score
    const rawWeightedScore =
      textScore * wText +
      urlScore * wUrl +
      reputationScore * wRep +
      patternScore * wPattern +
      impersonationScore * wImp +
      fileScore * wFile +
      communityScore * wComm +
      aiScore * wAi;

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

    let finalRiskScore = rawWeightedScore;

    if (hasCriticalOverride) {
      finalRiskScore = Math.max(finalRiskScore, config.criticalRules.criticalThreshold);
    } else {
      const triggeringDetectors = collection.detectorResults.filter(
        (r) => r.score >= config.correlationBoost.minScoreThreshold
      );

      if (
        config.correlationBoost.enabled &&
        triggeringDetectors.length >= config.correlationBoost.minTriggeringDetectors
      ) {
        const boosted = rawWeightedScore * config.correlationBoost.boostMultiplier;
        finalRiskScore = Math.min(100, Math.max(boosted, maxIndividualScore));
      } else {
        finalRiskScore = rawWeightedScore;
      }
    }

    const normalizedRiskScore = Math.min(100, Math.max(0, Math.round(finalRiskScore)));

    // 4. Calculate Orthogonal Confidence Score
    const distinctTriggered = new Set(triggeredDetectors).size;
    const confidence = this.calculateConfidence(
      collection,
      rawSignals,
      hasCriticalOverride,
      distinctTriggered
    );

    // 5. 2D Classification State
    const assessmentState = this.configManager.classifyState(normalizedRiskScore, confidence);

    // Map to RiskClassification
    let classification: RiskClassification;
    if (assessmentState === 'INSUFFICIENT_EVIDENCE') {
      classification = 'Insufficient Evidence';
    } else if (assessmentState === 'CONFIRMED_MALICIOUS') {
      classification = 'Critical Risk';
    } else {
      classification = this.configManager.classifyScore(normalizedRiskScore);
    }

    // Map to legacy ThreatLevel
    let threatLevel: ThreatLevel = 'SAFE';
    switch (assessmentState) {
      case 'CONFIRMED_MALICIOUS':
        threatLevel = 'MALICIOUS';
        break;
      case 'HIGH_RISK':
        threatLevel = 'HIGH_RISK';
        break;
      case 'SUSPICIOUS':
        threatLevel = 'SUSPICIOUS';
        break;
      case 'INSUFFICIENT_EVIDENCE':
        threatLevel = normalizedRiskScore >= 50 ? 'SUSPICIOUS' : 'LOW_RISK';
        break;
      case 'SAFE_LOW_RISK':
      default:
        threatLevel = 'SAFE';
        break;
    }

    // 6. Formulate Recommended Action & Structured Evidence
    const recommendedAction = this.configManager.getRecommendedAction(assessmentState);

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

    let evidenceSummary = '';
    if (assessmentState === 'INSUFFICIENT_EVIDENCE') {
      evidenceSummary = `Insufficient evidence: Confidence (${confidence}%) is below minimum threshold to provide a definitive assessment. Flagged ${collection.indicators.length} uncorroborated indicators.`;
    } else if (collection.indicators.length > 0) {
      evidenceSummary = `Identified ${collection.indicators.length} threat indicators across ${triggeredDetectors.length} active detection signals (Confidence: ${confidence}%).`;
    } else {
      evidenceSummary = `Strong evidence that no significant scam indicators exist across ${collection.totalDetectorsRan} evaluated detectors (Confidence: ${confidence}%).`;
    }

    return {
      risk_score: normalizedRiskScore,
      classification,
      confidence,
      state: assessmentState,
      triggered_detectors: triggeredDetectors,
      evidence: {
        summary: evidenceSummary,
        indicators: collection.indicators,
        breakdown: evidenceBreakdown,
        criticalRulesTriggered,
      },
      recommended_action: recommendedAction,
      signals: rawSignals,
      de_correlated_signals: deCorrelatedSignals,
      correlation_groups: groups,

      // Backward-compatible properties
      riskScore: normalizedRiskScore,
      threatLevel,
      confidenceScore: confidence,
      evidenceBreakdown,
    };
  }

  /**
   * Calculates composite risk score using EvidenceWeights (Legacy interface)
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

    const state = this.configManager.classifyState(finalScore, confidence);
    const classification = state === 'INSUFFICIENT_EVIDENCE'
      ? 'Insufficient Evidence'
      : (state === 'CONFIRMED_MALICIOUS' ? 'Critical Risk' : this.configManager.classifyScore(finalScore));

    let threatLevel: ThreatLevel = 'SAFE';
    switch (state) {
      case 'CONFIRMED_MALICIOUS':
        threatLevel = 'MALICIOUS';
        break;
      case 'HIGH_RISK':
        threatLevel = 'HIGH_RISK';
        break;
      case 'SUSPICIOUS':
        threatLevel = 'SUSPICIOUS';
        break;
      case 'INSUFFICIENT_EVIDENCE':
        threatLevel = finalScore >= 50 ? 'SUSPICIOUS' : 'LOW_RISK';
        break;
      case 'SAFE_LOW_RISK':
      default:
        threatLevel = 'SAFE';
        break;
    }

    const recommendedAction = this.configManager.getRecommendedAction(state);

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
      state,
      triggered_detectors: triggered,
      evidence: {
        summary: `Computed weighted score from ${triggered.length} active signal categories.`,
        indicators: [],
        breakdown,
        criticalRulesTriggered: [],
      },
      recommended_action: recommendedAction,
      signals: [],
      de_correlated_signals: [],
      correlation_groups: {},

      riskScore: finalScore,
      threatLevel,
      confidenceScore: confidence,
      evidenceBreakdown: breakdown,
    };
  }
}

export const riskEngine = new RiskEngine();
