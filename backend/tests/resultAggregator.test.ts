import { describe, it, expect } from 'vitest';
import { aggregateResults } from '../src/scanners/aggregator/resultAggregator';
import { DetectionItem } from '../src/types';

describe('Result Aggregator & Threat Scoring', () => {
  it('should classify clean results as SAFE with low risk score', () => {
    const score = aggregateResults({
      targetType: 'FILE',
      detections: [],
      enginesEvaluated: ['HashEngine', 'MagicBytes', 'StaticAnalyzer', 'ClamAV'],
      safeFactorsObserved: ['Declared MIME matches magic bytes'],
    });

    expect(score.threatLevel).toBe('SAFE');
    expect(score.riskScore).toBeLessThanOrEqual(15);
    expect(score.maliciousEngines).toBe(0);
    expect(score.cleanEngines).toBe(4);
    expect(score.recommendations.length).toBeGreaterThan(0);
  });

  it('should categorize critical threats as MALICIOUS with high confidence', () => {
    const criticalDets: DetectionItem[] = [
      {
        engine: 'ClamAV',
        category: 'virus_detection',
        severity: 'critical',
        ruleId: 'CLAM-001',
        title: 'Trojan.Agent.Generic',
        description: 'Confirmed malware signature.',
      },
      {
        engine: 'MagicBytesEngine',
        category: 'extension_mismatch',
        severity: 'critical',
        ruleId: 'MB-001',
        title: 'Executable disguised as PDF',
        description: 'MIME mismatch.',
      },
    ];

    const score = aggregateResults({
      targetType: 'FILE',
      detections: criticalDets,
      enginesEvaluated: ['HashEngine', 'MagicBytes', 'StaticAnalyzer', 'ClamAV'],
    });

    expect(score.threatLevel).toBe('MALICIOUS');
    expect(score.riskScore).toBeGreaterThanOrEqual(85);
    expect(score.threatConfidence).toBe('HIGH');
    expect(score.maliciousEngines).toBeGreaterThanOrEqual(1);
    expect(score.recommendations.some((r) => r.includes('Do not run'))).toBe(true);
  });

  it('should classify medium anomalies as SUSPICIOUS', () => {
    const mediumDets: DetectionItem[] = [
      {
        engine: 'StaticAnalyzer',
        category: 'executable_risk',
        severity: 'medium',
        ruleId: 'SA-002',
        title: 'Direct Executable File',
        description: 'Standalone binary.',
      },
      {
        engine: 'URLSecurity',
        category: 'suspicious_tld',
        severity: 'medium',
        ruleId: 'URL-TLD-001',
        title: 'High risk TLD',
        description: 'Abuse prone TLD.',
      },
    ];

    const score = aggregateResults({
      targetType: 'URL',
      detections: mediumDets,
      enginesEvaluated: ['SSRFGuard', 'URLValidator', 'URLPhishingEngine'],
    });

    expect(score.threatLevel).toBe('SUSPICIOUS');
    expect(score.riskScore).toBeGreaterThanOrEqual(25);
  });
});
