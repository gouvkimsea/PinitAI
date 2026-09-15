import { describe, it, expect, beforeEach } from 'vitest';
import { riskEngine } from '../src/modules/risk/riskEngine';
import { riskConfigManager } from '../src/modules/risk/riskConfig';
import { EvidenceCollection } from '../src/pipeline/types';
import { ImpersonationDetector } from '../src/pipeline/detectors/impersonationDetector';

describe('Centralized Risk-Scoring Engine Tests', () => {
  beforeEach(() => {
    // Reset configuration to factory defaults before each test
    riskEngine.resetConfig();
  });

  describe('Category Bands & Classification (0-100)', () => {
    it('should classify 0-20 as Low Risk', () => {
      expect(riskConfigManager.classifyScore(0)).toBe('Low Risk');
      expect(riskConfigManager.classifyScore(10)).toBe('Low Risk');
      expect(riskConfigManager.classifyScore(20)).toBe('Low Risk');
    });

    it('should classify 21-40 as Mild Risk', () => {
      expect(riskConfigManager.classifyScore(21)).toBe('Mild Risk');
      expect(riskConfigManager.classifyScore(30)).toBe('Mild Risk');
      expect(riskConfigManager.classifyScore(40)).toBe('Mild Risk');
    });

    it('should classify 41-60 as Suspicious', () => {
      expect(riskConfigManager.classifyScore(41)).toBe('Suspicious');
      expect(riskConfigManager.classifyScore(50)).toBe('Suspicious');
      expect(riskConfigManager.classifyScore(60)).toBe('Suspicious');
    });

    it('should classify 61-80 as High Risk', () => {
      expect(riskConfigManager.classifyScore(61)).toBe('High Risk');
      expect(riskConfigManager.classifyScore(70)).toBe('High Risk');
      expect(riskConfigManager.classifyScore(80)).toBe('High Risk');
    });

    it('should classify 81-100 as Critical Risk', () => {
      expect(riskConfigManager.classifyScore(81)).toBe('Critical Risk');
      expect(riskConfigManager.classifyScore(95)).toBe('Critical Risk');
      expect(riskConfigManager.classifyScore(100)).toBe('Critical Risk');
    });
  });

  describe('Structured Result Contract', () => {
    it('should return all required properties: risk_score, classification, confidence, triggered_detectors, evidence, recommended_action', () => {
      const mockCollection: EvidenceCollection = {
        detectorResults: [
          {
            detector_name: 'text_linguistic_detector',
            detector_type: 'text',
            score: 50,
            severity: 'medium',
            confidence: 80,
            evidence: { summary: 'Urgent phrasing found', indicators: ['Urgency'] },
            execution_time_ms: 10,
          },
          {
            detector_name: 'scam_pattern_detector',
            detector_type: 'pattern',
            score: 55,
            severity: 'medium',
            confidence: 85,
            evidence: { summary: 'Bank impersonation pattern', indicators: ['Banking scam'] },
            execution_time_ms: 12,
          },
        ],
        totalDetectorsRan: 2,
        cleanCount: 0,
        suspiciousCount: 2,
        maliciousCount: 0,
        indicators: ['Urgency', 'Banking scam'],
        detectedThreatCategories: ['PHISHING'],
      };

      const result = riskEngine.evaluateEvidence(mockCollection);

      // Verify required fields
      expect(result).toHaveProperty('risk_score');
      expect(typeof result.risk_score).toBe('number');
      expect(result.risk_score).toBeGreaterThanOrEqual(0);
      expect(result.risk_score).toBeLessThanOrEqual(100);

      expect(result).toHaveProperty('classification');
      expect(['Low Risk', 'Mild Risk', 'Suspicious', 'High Risk', 'Critical Risk']).toContain(result.classification);

      expect(result).toHaveProperty('confidence');
      expect(typeof result.confidence).toBe('number');
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(100);

      expect(result).toHaveProperty('triggered_detectors');
      expect(Array.isArray(result.triggered_detectors)).toBe(true);
      expect(result.triggered_detectors).toContain('text_linguistic_detector');
      expect(result.triggered_detectors).toContain('scam_pattern_detector');

      expect(result).toHaveProperty('evidence');
      expect(result.evidence).toHaveProperty('summary');
      expect(result.evidence).toHaveProperty('indicators');
      expect(result.evidence).toHaveProperty('breakdown');
      expect(result.evidence).toHaveProperty('criticalRulesTriggered');

      expect(result).toHaveProperty('recommended_action');
      expect(typeof result.recommended_action).toBe('string');
      expect(result.recommended_action.length).toBeGreaterThan(10);

      // Verify backward-compatible aliases
      expect(result).toHaveProperty('riskScore');
      expect(result).toHaveProperty('threatLevel');
      expect(result).toHaveProperty('confidenceScore');
      expect(result).toHaveProperty('evidenceBreakdown');
    });
  });

  describe('Anti-Unilateral Rule vs Configured Critical Security Rules', () => {
    it('should NOT allow a single standard detector to unilaterally dictate the final result without critical rule match', () => {
      // Setup: 5 detectors ran. 1 standard text detector flagged 80, but all other 4 detectors are clean (0)
      const mockCollection: EvidenceCollection = {
        detectorResults: [
          {
            detector_name: 'text_linguistic_detector',
            detector_type: 'text',
            score: 80, // High individual score
            severity: 'high',
            confidence: 80,
            evidence: { summary: 'Urgent tone', indicators: ['Urgent words'] },
            execution_time_ms: 10,
          },
          {
            detector_name: 'url_security_detector',
            detector_type: 'url',
            score: 0,
            severity: 'safe',
            confidence: 90,
            evidence: { summary: 'Clean URL', indicators: [] },
            execution_time_ms: 5,
          },
          {
            detector_name: 'reputation_signal_detector',
            detector_type: 'reputation',
            score: 0,
            severity: 'safe',
            confidence: 80,
            evidence: { summary: 'Clean Domain', indicators: [] },
            execution_time_ms: 8,
          },
          {
            detector_name: 'scam_pattern_detector',
            detector_type: 'pattern',
            score: 0,
            severity: 'safe',
            confidence: 80,
            evidence: { summary: 'No patterns', indicators: [] },
            execution_time_ms: 6,
          },
          {
            detector_name: 'impersonation_detector',
            detector_type: 'impersonation',
            score: 0,
            severity: 'safe',
            confidence: 80,
            evidence: { summary: 'No impersonation', indicators: [] },
            execution_time_ms: 7,
          },
        ],
        totalDetectorsRan: 5,
        cleanCount: 4,
        suspiciousCount: 0,
        maliciousCount: 1,
        indicators: ['Urgent words'],
        detectedThreatCategories: ['SPAM'],
      };

      const result = riskEngine.evaluateEvidence(mockCollection);

      // Because text has a weight of ~0.15-0.20 among active detectors, the single non-critical detector
      // must NOT unilaterally force the final score to 80 (High/Critical Risk).
      // The weighted score should remain proportional (e.g. <= 25).
      expect(result.risk_score).toBeLessThanOrEqual(25);
      expect(result.classification).not.toBe('High Risk');
      expect(result.classification).not.toBe('Critical Risk');
      expect(result.evidence.criticalRulesTriggered).toEqual([]);
    });

    it('should allow an explicitly configured critical security rule to trigger a critical override', () => {
      // Setup: File analysis detector flagged a verified malware signature (score 95)
      // which matches critical rule 'MALWARE_SIGNATURE_DETECTED'
      const mockCollection: EvidenceCollection = {
        detectorResults: [
          {
            detector_name: 'file_security_detector',
            detector_type: 'file',
            score: 95,
            severity: 'critical',
            confidence: 95,
            evidence: { summary: 'ClamAV detected Win.Trojan.Generic', indicators: ['Trojan signature'] },
            execution_time_ms: 45,
          },
          {
            detector_name: 'reputation_signal_detector',
            detector_type: 'reputation',
            score: 0,
            severity: 'safe',
            confidence: 70,
            evidence: { summary: 'Clean reputation', indicators: [] },
            execution_time_ms: 10,
          },
          {
            detector_name: 'community_intelligence_detector',
            detector_type: 'community',
            score: 0,
            severity: 'safe',
            confidence: 60,
            evidence: { summary: 'No community reports', indicators: [] },
            execution_time_ms: 12,
          },
        ],
        totalDetectorsRan: 3,
        cleanCount: 2,
        suspiciousCount: 0,
        maliciousCount: 1,
        indicators: ['Trojan signature'],
        detectedThreatCategories: ['MALWARE'],
      };

      const result = riskEngine.evaluateEvidence(mockCollection);

      // Critical security rule override MUST apply
      expect(result.risk_score).toBeGreaterThanOrEqual(85);
      expect(result.classification).toBe('Critical Risk');
      expect(result.evidence.criticalRulesTriggered).toContain('MALWARE_SIGNATURE_DETECTED');
      expect(result.confidence).toBeGreaterThanOrEqual(95);
    });

    it('should respect allowCriticalOverrides toggle when disabled', () => {
      // Disable critical rule overrides
      riskEngine.updateConfig({
        criticalRules: {
          allowCriticalOverrides: false,
          criticalThreshold: 85,
          rules: riskEngine.getConfig().criticalRules.rules,
        },
      });

      const mockCollection: EvidenceCollection = {
        detectorResults: [
          {
            detector_name: 'file_security_detector',
            detector_type: 'file',
            score: 95,
            severity: 'critical',
            confidence: 95,
            evidence: { summary: 'Trojan payload', indicators: ['Trojan'] },
            execution_time_ms: 30,
          },
          {
            detector_name: 'reputation_signal_detector',
            detector_type: 'reputation',
            score: 0,
            severity: 'safe',
            confidence: 80,
            evidence: { summary: 'Clean', indicators: [] },
            execution_time_ms: 10,
          },
          {
            detector_name: 'community_intelligence_detector',
            detector_type: 'community',
            score: 0,
            severity: 'safe',
            confidence: 80,
            evidence: { summary: 'Clean', indicators: [] },
            execution_time_ms: 10,
          },
        ],
        totalDetectorsRan: 3,
        cleanCount: 2,
        suspiciousCount: 0,
        maliciousCount: 1,
        indicators: ['Trojan'],
        detectedThreatCategories: ['MALWARE'],
      };

      const result = riskEngine.evaluateEvidence(mockCollection);

      // With overrides disabled and only 1 detector triggering, score should be weighted
      // rather than automatically forced to 85+
      expect(result.risk_score).toBeLessThan(80);
      expect(result.evidence.criticalRulesTriggered).toEqual([]);
    });
  });

  describe('Configurable Weights Without Code Rewrites', () => {
    it('should change risk calculation when weights are updated at runtime', () => {
      const mockCollection: EvidenceCollection = {
        detectorResults: [
          {
            detector_name: 'text_linguistic_detector',
            detector_type: 'text',
            score: 70,
            severity: 'high',
            confidence: 80,
            evidence: { summary: 'Urgent', indicators: ['Urgency'] },
            execution_time_ms: 10,
          },
          {
            detector_name: 'url_security_detector',
            detector_type: 'url',
            score: 20,
            severity: 'low',
            confidence: 80,
            evidence: { summary: 'Minor query issue', indicators: [] },
            execution_time_ms: 10,
          },
        ],
        totalDetectorsRan: 2,
        cleanCount: 0,
        suspiciousCount: 1,
        maliciousCount: 1,
        indicators: ['Urgency'],
        detectedThreatCategories: ['PHISHING'],
      };

      // Initial calculation with default weights
      const initialResult = riskEngine.evaluateEvidence(mockCollection);

      // Now heavily weight text analysis (e.g. text: 0.90, url: 0.10)
      riskEngine.updateConfig({
        weights: {
          ...riskEngine.getConfig().weights,
          textAnalysis: 0.90,
          urlAnalysis: 0.10,
        },
      });

      const updatedResult = riskEngine.evaluateEvidence(mockCollection);

      // Heavily weighting text (score 70) should increase the composite risk score
      expect(updatedResult.risk_score).toBeGreaterThan(initialResult.risk_score);

      // Reset weights and verify
      riskEngine.resetConfig();
      const resetResult = riskEngine.evaluateEvidence(mockCollection);
      expect(resetResult.risk_score).toBe(initialResult.risk_score);
    });
  });

  describe('Impersonation Detection Signal', () => {
    it('should flag financial and authority impersonation correctly', async () => {
      const detector = new ImpersonationDetector();
      const input = {
        type: 'TEXT' as const,
        raw: 'URGENT: This is ABA Bank Security. Your account is frozen due to suspected fraud. Contact us immediately or face legal arrest.',
        normalizedText: 'urgent: this is aba bank security. your account is frozen due to suspected fraud. contact us immediately or face legal arrest.',
        extractedUrls: [],
        extractedPhoneNumbers: [],
      };

      const result = await detector.detect(input, { scanId: 'test-imp-1', startTime: Date.now() });

      expect(result).not.toBeNull();
      expect(result!.score).toBeGreaterThanOrEqual(65);
      expect(['high', 'critical']).toContain(result!.severity);
      expect(result!.evidence.indicators.some((ind) => ind.includes('ABA Bank'))).toBe(true);
      expect(result!.evidence.indicators.some((ind) => ind.includes('Coercive Impersonation'))).toBe(true);
    });

    it('should detect brand combisquatting in URLs', async () => {
      const detector = new ImpersonationDetector();
      const input = {
        type: 'URL' as const,
        raw: 'http://paypal-verification-update.phishingsite.net/login',
        normalizedUrl: 'http://paypal-verification-update.phishingsite.net/login',
        extractedUrls: ['http://paypal-verification-update.phishingsite.net/login'],
        extractedPhoneNumbers: [],
      };

      const result = await detector.detect(input, { scanId: 'test-imp-2', startTime: Date.now() });

      expect(result).not.toBeNull();
      expect(result!.score).toBeGreaterThanOrEqual(75);
      expect(result!.evidence.indicators.some((ind) => ind.includes('Combisquatting'))).toBe(true);
    });
  });

  describe('Multi-Detector Correlation Boosting', () => {
    it('should boost composite score and confidence when multiple independent detectors confirm threats', () => {
      const mockCollection: EvidenceCollection = {
        detectorResults: [
          {
            detector_name: 'text_linguistic_detector',
            detector_type: 'text',
            score: 65,
            severity: 'high',
            confidence: 80,
            evidence: { summary: 'Urgent phrasing', indicators: ['Urgency'] },
            execution_time_ms: 10,
          },
          {
            detector_name: 'scam_pattern_detector',
            detector_type: 'pattern',
            score: 70,
            severity: 'high',
            confidence: 85,
            evidence: { summary: 'Lottery prize claim scheme', indicators: ['Prize claim'] },
            execution_time_ms: 12,
          },
          {
            detector_name: 'impersonation_detector',
            detector_type: 'impersonation',
            score: 75,
            severity: 'high',
            confidence: 85,
            evidence: { summary: 'ABA Bank impersonation', indicators: ['Bank impersonation'] },
            execution_time_ms: 11,
          },
        ],
        totalDetectorsRan: 3,
        cleanCount: 0,
        suspiciousCount: 0,
        maliciousCount: 3,
        indicators: ['Urgency', 'Prize claim', 'Bank impersonation'],
        detectedThreatCategories: ['PHISHING', 'PRIZE_SCAM'],
      };

      const result = riskEngine.evaluateEvidence(mockCollection);

      // Multi-detector consensus should boost score into High or Critical Risk
      expect(result.risk_score).toBeGreaterThanOrEqual(65);
      expect(['High Risk', 'Critical Risk']).toContain(result.classification);
      expect(result.confidence).toBeGreaterThanOrEqual(90);
      expect(result.triggered_detectors.length).toBe(3);
    });
  });
});
