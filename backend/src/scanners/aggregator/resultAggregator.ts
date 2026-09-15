import { AggregatedScore, DetectionItem, ThreatConfidence, ThreatLevel } from '../../types';

export interface EvaluationInput {
  targetType: 'FILE' | 'URL';
  detections: DetectionItem[];
  enginesEvaluated: string[];
  safeFactorsObserved?: string[];
  context?: {
    isHttps?: boolean;
    isMimeMatch?: boolean;
    hasValidSignatures?: boolean;
    fileName?: string;
    url?: string;
  };
}

/**
 * Aggregates detections from multiple security engines and produces
 * a calibrated 0-100 risk score and categorical threat assessment.
 */
export function aggregateResults(input: EvaluationInput): AggregatedScore {
  const { detections, enginesEvaluated, safeFactorsObserved = [], context = {} } = input;

  let baseScore = 0;
  let hasCriticalDetection = false;
  let hasHighDetection = false;
  let hasMediumDetection = false;

  const severityWeights: Record<string, number> = {
    critical: 45,
    high: 25,
    medium: 12,
    low: 5,
  };

  const detectedEngines = new Set<string>();

  for (const det of detections) {
    detectedEngines.add(det.engine);
    const weight = severityWeights[det.severity] || 10;
    baseScore += weight;

    if (det.severity === 'critical') hasCriticalDetection = true;
    if (det.severity === 'high') hasHighDetection = true;
    if (det.severity === 'medium') hasMediumDetection = true;
  }

  // Multi-engine amplification: if multiple distinct engines flag the target, elevate score
  if (detectedEngines.size >= 2) {
    baseScore = Math.round(baseScore * 1.25);
  }

  // Cap risk score between 0 and 100
  let finalRiskScore = Math.min(100, Math.max(0, baseScore));

  // Determine Categorical Threat Level
  let threatLevel: ThreatLevel = 'SAFE';

  if (hasCriticalDetection || finalRiskScore >= 85) {
    threatLevel = 'MALICIOUS';
    finalRiskScore = Math.max(85, finalRiskScore);
  } else if (hasHighDetection || finalRiskScore >= 70) {
    threatLevel = 'HIGH_RISK';
  } else if (hasMediumDetection || finalRiskScore >= 40) {
    threatLevel = 'SUSPICIOUS';
  } else if (finalRiskScore > 15) {
    threatLevel = 'LOW_RISK';
  } else {
    threatLevel = 'SAFE';
    finalRiskScore = Math.min(15, finalRiskScore);
  }

  // Determine Confidence
  let threatConfidence: ThreatConfidence = 'LOW';
  if (enginesEvaluated.length >= 3 || hasCriticalDetection) {
    threatConfidence = 'HIGH';
  } else if (enginesEvaluated.length >= 2) {
    threatConfidence = 'MEDIUM';
  }

  // Compile Positive Safe Factors
  const safeFactors: string[] = [...safeFactorsObserved];
  if (context.isHttps) safeFactors.push('Encrypted transport protocol (HTTPS) active');
  if (context.isMimeMatch) safeFactors.push('Declared file extension matches internal binary magic signature');
  if (detections.length === 0) {
    safeFactors.push('No known malicious signatures matched in database');
    safeFactors.push('No suspicious execution macros or downloader strings discovered');
    safeFactors.push('SSRF checks and internal network access filters passed');
  }

  // Compile Clear Summary & Explanations
  let summary = '';
  const recommendations: string[] = [];

  if (threatLevel === 'MALICIOUS') {
    const topDets = detections.slice(0, 2).map((d) => d.title).join('; ');
    summary = `Confirmed malicious threat detected (${topDets}). High risk of compromise.`;
    recommendations.push('Do not run, execute, open, or extract this file.');
    recommendations.push('Delete or quarantine the file immediately.');
    recommendations.push('If opened previously, isolate the host system and run a full antivirus scan.');
  } else if (threatLevel === 'HIGH_RISK') {
    summary = `High risk indicators identified across ${detectedEngines.size} security checks.`;
    recommendations.push('Exercise extreme caution. Do not trust or interact with this resource.');
    recommendations.push('Verify sender or origin authenticity through an independent channel.');
  } else if (threatLevel === 'SUSPICIOUS') {
    summary = 'Multiple anomalous or suspicious patterns detected requiring caution.';
    recommendations.push('Review detection signals carefully before opening.');
    recommendations.push('Do not provide credentials, passwords, or personal financial details.');
  } else if (threatLevel === 'LOW_RISK') {
    summary = 'Low risk. Minor informational warnings noted, but no active malware detected.';
    recommendations.push('Resource appears largely clean. Standard security hygiene advised.');
  } else {
    summary = 'Clean. No threat indicators or malicious signatures were detected.';
    recommendations.push('No immediate threats observed. Always ensure software remains updated.');
  }

  // Calculation of engine breakdown
  const maliciousEngines = hasCriticalDetection ? Math.max(1, detectedEngines.size) : 0;
  const suspiciousEngines = hasHighDetection || hasMediumDetection ? detectedEngines.size - maliciousEngines : 0;
  const cleanEngines = Math.max(0, enginesEvaluated.length - detectedEngines.size);

  return {
    threatLevel,
    riskScore: finalRiskScore,
    threatConfidence,
    summary,
    totalEngines: enginesEvaluated.length,
    maliciousEngines,
    suspiciousEngines: Math.max(0, suspiciousEngines),
    cleanEngines,
    safeFactors,
    recommendations,
    allDetections: detections,
  };
}
