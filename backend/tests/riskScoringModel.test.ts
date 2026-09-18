import { describe, it, expect, beforeEach } from 'vitest';
import { riskEngine } from '../src/modules/risk/riskEngine';
import { riskConfigManager } from '../src/modules/risk/riskConfig';
import { EvidenceCollection } from '../src/pipeline/types';
import { EvidenceSignal } from '../src/modules/risk/types';

describe('Redesigned Evidence-Based Risk Scoring Model Tests', () => {
  beforeEach(() => {
    riskEngine.resetConfig();
  });

  describe('1. Orthogonal Risk vs. Confidence Separation', () => {
    it('High Risk + Low Confidence: potentially dangerous but insufficient evidence', () => {
      // Scenario: A single detector flagged a high risk indicator (e.g. obscure heuristic score 85),
      // but only 1 detector ran with 0 corroboration from other detectors.
      const collection: EvidenceCollection = {
        detectorResults: [
          {
            detector_name: 'text_linguistic_detector',
            detector_type: 'text',
            score: 85,
            severity: 'high',
            confidence: 30, // low certainty in extraction
            evidence: {
              summary: 'Possible threat phrasing found in ambiguous short text',
              indicators: ['Unusual coercive phrasing'],
            },
            execution_time_ms: 8,
          },
        ],
        totalDetectorsRan: 1, // Sparse coverage
        cleanCount: 0,
        suspiciousCount: 0,
        maliciousCount: 1,
        indicators: ['Unusual coercive phrasing'],
        detectedThreatCategories: ['SOCIAL_ENGINEERING'],
        highestSeverity: 'high',
      };

      const result = riskEngine.evaluateEvidence(collection);

      // High raw detector signal results in risk score, but confidence must be low (< 45)
      expect(result.risk_score).toBeGreaterThanOrEqual(70);
      expect(result.confidence).toBeLessThan(45);
      // Because confidence is insufficient (< 40), the state must be INSUFFICIENT_EVIDENCE
      expect(result.state).toBe('INSUFFICIENT_EVIDENCE');
      expect(result.classification).toBe('Insufficient Evidence');
      expect(result.recommended_action).toContain('INSUFFICIENT EVIDENCE');
    });

    it('Low Risk + High Confidence: strong evidence that no significant scam indicators were found', () => {
      // Scenario: 6 independent detection engines all evaluated the sample and found zero malicious indicators.
      const collection: EvidenceCollection = {
        detectorResults: [
          {
            detector_name: 'text_linguistic_detector',
            detector_type: 'text',
            score: 0,
            severity: 'safe',
            confidence: 90,
            evidence: { summary: 'Standard conversational text', indicators: [] },
            execution_time_ms: 10,
          },
          {
            detector_name: 'url_security_detector',
            detector_type: 'url',
            score: 0,
            severity: 'safe',
            confidence: 95,
            evidence: { summary: 'Clean URL structure', indicators: [] },
            execution_time_ms: 8,
          },
          {
            detector_name: 'reputation_signal_detector',
            detector_type: 'reputation',
            score: 0,
            severity: 'safe',
            confidence: 92,
            evidence: { summary: 'Reputable domain with long history', indicators: [] },
            execution_time_ms: 12,
          },
          {
            detector_name: 'scam_pattern_detector',
            detector_type: 'pattern',
            score: 0,
            severity: 'safe',
            confidence: 88,
            evidence: { summary: 'No scam patterns detected', indicators: [] },
            execution_time_ms: 7,
          },
          {
            detector_name: 'impersonation_detector',
            detector_type: 'impersonation',
            score: 0,
            severity: 'safe',
            confidence: 90,
            evidence: { summary: 'No entity impersonation', indicators: [] },
            execution_time_ms: 9,
          },
          {
            detector_name: 'community_intelligence_detector',
            detector_type: 'community',
            score: 0,
            severity: 'safe',
            confidence: 85,
            evidence: { summary: 'Zero community reports filed', indicators: [] },
            execution_time_ms: 11,
          },
        ],
        totalDetectorsRan: 6,
        cleanCount: 6,
        suspiciousCount: 0,
        maliciousCount: 0,
        indicators: [],
        detectedThreatCategories: [],
        highestSeverity: 'safe',
      };

      const result = riskEngine.evaluateEvidence(collection);

      expect(result.risk_score).toBeLessThanOrEqual(20);
      expect(result.confidence).toBeGreaterThanOrEqual(85);
      expect(result.state).toBe('SAFE_LOW_RISK');
      expect(result.classification).toBe('Low Risk');
      expect(result.threatLevel).toBe('SAFE');
      expect(result.evidence.summary).toContain('Strong evidence that no significant scam indicators exist');
    });
  });

  describe('2. Evidence-Based Signals Contract (7 Required Attributes)', () => {
    it('every extracted signal must include: source, signalType, severity, reliability, confidence, timestamp, explanation', () => {
      const collection: EvidenceCollection = {
        detectorResults: [
          {
            detector_name: 'url_security_detector',
            detector_type: 'url',
            score: 65,
            severity: 'high',
            confidence: 85,
            evidence: {
              summary: 'Suspicious domain entropy and deceptive redirect',
              indicators: [
                'High domain name Shannon entropy (>4.2)',
                'Unusual top-level domain (.buzz)',
              ],
            },
            execution_time_ms: 15,
          },
        ],
        totalDetectorsRan: 1,
        cleanCount: 0,
        suspiciousCount: 0,
        maliciousCount: 1,
        indicators: [
          'High domain name Shannon entropy (>4.2)',
          'Unusual top-level domain (.buzz)',
        ],
        detectedThreatCategories: ['SUSPICIOUS_URL'],
        highestSeverity: 'high',
      };

      const signals = riskEngine.extractSignals(collection);

      expect(signals.length).toBe(2);

      for (const sig of signals) {
        // Required Field 1: source
        expect(sig).toHaveProperty('source');
        expect(typeof sig.source).toBe('string');
        expect(sig.source).toBe('url_security_detector');

        // Required Field 2: signalType
        expect(sig).toHaveProperty('signalType');
        expect(typeof sig.signalType).toBe('string');
        expect(sig.signalType).toBe('url');

        // Required Field 3: severity
        expect(sig).toHaveProperty('severity');
        expect(['safe', 'low', 'medium', 'high', 'critical']).toContain(sig.severity);
        expect(sig.severity).toBe('high');

        // Required Field 4: reliability
        expect(sig).toHaveProperty('reliability');
        expect(typeof sig.reliability).toBe('number');
        expect(sig.reliability).toBeGreaterThan(0);
        expect(sig.reliability).toBeLessThanOrEqual(1.0);

        // Required Field 5: confidence
        expect(sig).toHaveProperty('confidence');
        expect(typeof sig.confidence).toBe('number');
        expect(sig.confidence).toBeGreaterThanOrEqual(0);
        expect(sig.confidence).toBeLessThanOrEqual(100);

        // Required Field 6: timestamp
        expect(sig).toHaveProperty('timestamp');
        expect(typeof sig.timestamp).toBe('string');
        expect(!isNaN(Date.parse(sig.timestamp))).toBe(true);

        // Required Field 7: explanation
        expect(sig).toHaveProperty('explanation');
        expect(typeof sig.explanation).toBe('string');
        expect(sig.explanation.length).toBeGreaterThan(5);
      }
    });
  });

  describe('3. Preventing Double-Counting of Correlated Signals', () => {
    it('five URL features derived from the same domain structure should NOT artificially inflate the score into critical', () => {
      // Create 5 signals all derived from the same underlying domain characteristics
      const mockSignals: EvidenceSignal[] = [
        {
          id: 'sig-1',
          source: 'url_security_detector',
          signalType: 'url',
          severity: 'medium',
          reliability: 0.8,
          confidence: 80,
          timestamp: new Date().toISOString(),
          explanation: 'High domain name Shannon entropy',
          score: 45,
          correlationGroup: 'url:domain_structure',
        },
        {
          id: 'sig-2',
          source: 'url_security_detector',
          signalType: 'url',
          severity: 'medium',
          reliability: 0.8,
          confidence: 80,
          timestamp: new Date().toISOString(),
          explanation: 'Excessive hyphen count in domain name',
          score: 40,
          correlationGroup: 'url:domain_structure',
        },
        {
          id: 'sig-3',
          source: 'url_security_detector',
          signalType: 'url',
          severity: 'medium',
          reliability: 0.8,
          confidence: 80,
          timestamp: new Date().toISOString(),
          explanation: 'Digit-to-alphabet ratio anomaly in domain',
          score: 35,
          correlationGroup: 'url:domain_structure',
        },
        {
          id: 'sig-4',
          source: 'url_security_detector',
          signalType: 'url',
          severity: 'medium',
          reliability: 0.8,
          confidence: 80,
          timestamp: new Date().toISOString(),
          explanation: 'Unusual top-level domain (.xyz)',
          score: 35,
          correlationGroup: 'url:domain_structure',
        },
        {
          id: 'sig-5',
          source: 'url_security_detector',
          signalType: 'url',
          severity: 'medium',
          reliability: 0.8,
          confidence: 80,
          timestamp: new Date().toISOString(),
          explanation: 'Excessive subdomain depth',
          score: 30,
          correlationGroup: 'url:domain_structure',
        },
      ];

      const { deCorrelatedSignals, groups } = riskEngine.deCorrelateSignals(mockSignals);

      // Verify that all 5 signals were captured into a single correlation group
      expect(groups['url:domain_structure']).toBeDefined();
      expect(groups['url:domain_structure'].signals.length).toBe(5);

      // The primary signal should be the highest weighted score (45)
      expect(groups['url:domain_structure'].primarySignal.explanation).toContain('entropy');

      // Effective score should dampen the 4 secondary signals with dampeningFactor (0.25)
      // Linear sum would be 45 + 40 + 35 + 35 + 30 = 185 (would overflow or max at 100)
      // Dampened effective score: 45 + (40 + 35 + 35 + 30) * 0.25 = 45 + 140 * 0.25 = 45 + 35 = 80
      const effectiveGroupScore = groups['url:domain_structure'].effectiveScore;
      expect(effectiveGroupScore).toBeLessThan(85);
      expect(effectiveGroupScore).toBe(80);

      // The deCorrelatedSignals array must contain exactly 1 combined representative for this group
      expect(deCorrelatedSignals.length).toBe(1);
      expect(deCorrelatedSignals[0].score).toBe(80);
    });
  });

  describe('4. Clear Thresholds & State Boundaries', () => {
    it('should classify safe/low risk boundary correctly', () => {
      // Risk <= 20 with adequate confidence -> SAFE_LOW_RISK
      expect(riskConfigManager.classifyState(0, 80)).toBe('SAFE_LOW_RISK');
      expect(riskConfigManager.classifyState(15, 75)).toBe('SAFE_LOW_RISK');
      expect(riskConfigManager.classifyState(20, 70)).toBe('SAFE_LOW_RISK');
    });

    it('should classify suspicious boundary correctly', () => {
      // Risk 21-60 with adequate confidence -> SUSPICIOUS
      expect(riskConfigManager.classifyState(25, 60)).toBe('SUSPICIOUS');
      expect(riskConfigManager.classifyState(45, 65)).toBe('SUSPICIOUS');
      expect(riskConfigManager.classifyState(59, 70)).toBe('SUSPICIOUS');
    });

    it('should classify high risk boundary correctly', () => {
      // Risk 60-79 (or risk >= 80 with moderate confidence < 70) -> HIGH_RISK
      expect(riskConfigManager.classifyState(65, 60)).toBe('HIGH_RISK');
      expect(riskConfigManager.classifyState(75, 65)).toBe('HIGH_RISK');
      expect(riskConfigManager.classifyState(85, 65)).toBe('HIGH_RISK'); // high risk but confidence < 70
    });

    it('should classify confirmed malicious boundary correctly', () => {
      // Risk >= 80 with high confidence >= 70 -> CONFIRMED_MALICIOUS
      expect(riskConfigManager.classifyState(80, 70)).toBe('CONFIRMED_MALICIOUS');
      expect(riskConfigManager.classifyState(90, 85)).toBe('CONFIRMED_MALICIOUS');
      expect(riskConfigManager.classifyState(100, 95)).toBe('CONFIRMED_MALICIOUS');
    });

    it('should allow an explicit unknown/insufficient evidence state', () => {
      // Confidence < 40 triggers INSUFFICIENT_EVIDENCE regardless of nominal score
      expect(riskConfigManager.classifyState(10, 35)).toBe('INSUFFICIENT_EVIDENCE');
      expect(riskConfigManager.classifyState(50, 30)).toBe('INSUFFICIENT_EVIDENCE');
      expect(riskConfigManager.classifyState(75, 38)).toBe('INSUFFICIENT_EVIDENCE');
    });
  });
});
