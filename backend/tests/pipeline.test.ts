import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import prisma from '../src/database/client';
import { textNormalizer } from '../src/pipeline/normalization/textNormalizer';
import { urlNormalizer } from '../src/pipeline/normalization/urlNormalizer';
import { fileNormalizer } from '../src/pipeline/normalization/fileNormalizer';
import { scamPatternDetector } from '../src/pipeline/detectors/patternDetector';
import { textAnalysisDetector } from '../src/pipeline/detectors/textDetector';
import { urlAnalysisDetector } from '../src/pipeline/detectors/urlDetector';
import { communityReportDetector } from '../src/pipeline/detectors/communityReportDetector';
import { detectorRegistry } from '../src/pipeline/registry/detectorRegistry';
import { riskEngine } from '../src/modules/risk/riskEngine';
import { detectionPipeline } from '../src/pipeline/orchestrator';
import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult } from '../src/pipeline/types';

describe('Multi-Layer Scam Detection Pipeline Tests', () => {
  beforeAll(async () => {
    // Seed a community scam report for testing communityReportDetector
    await prisma.scamReport.create({
      data: {
        scamType: 'phishing',
        target: 'https://known-community-scam.xyz',
        description: 'Phishing portal impersonating ABA Bank with fake login prompt.',
        status: 'CONFIRMED',
      },
    });
  });

  afterAll(async () => {
    await prisma.scamReport.deleteMany({
      where: { target: 'https://known-community-scam.xyz' },
    });
    await prisma.$disconnect();
  });

  describe('1. Normalization Layer', () => {
    it('should strip zero-width and invisible evasion characters from text', () => {
      // "Urgent" with zero-width spaces (\u200B) injected between characters to evade filters
      const obfuscated = 'U\u200Br\u200Bg\u200Be\u200Bn\u200Bt: Verify your password immediately!';
      const result = textNormalizer.normalize(obfuscated);
      expect(result.cleanedText).toBe('Urgent: Verify your password immediately!');
      expect(result.detectedLanguage).toBe('en');
    });

    it('should de-obfuscate leetspeak for pattern matching', () => {
      const leetText = 'P@ssw0rd v3rify n0w!';
      const result = textNormalizer.normalize(leetText);
      expect(result.deobfuscatedText).toContain('password verify now');
    });

    it('should clean tracking parameters and normalize URLs', () => {
      const messyUrl = 'HTTP://Example.COM:80/login/?utm_source=telegram&fbclid=12345#ref';
      const result = urlNormalizer.normalize(messyUrl);
      expect(result.normalizedUrl).toBe('http://example.com/login');
      expect(result.hasTrackingParams).toBe(true);
      expect(result.domain).toBe('example.com');
    });

    it('should flag deceptive double extension files', () => {
      const result = fileNormalizer.normalize('invoice_march.pdf.exe', 'application/x-msdownload');
      expect(result.isDoubleExtension).toBe(true);
      expect(result.doubleExtension).toBe('pdf.exe');
      expect(result.extension).toBe('exe');
    });
  });

  describe('2. Multiple Modular Detectors', () => {
    const mockContext: PipelineContext = {
      scanId: 'test-scan-id-123',
      startTime: Date.now(),
    };

    it('text_linguistic_detector should return structured DetectorResult for Khmer threat', async () => {
      const input: NormalizedInput = {
        type: 'TEXT',
        raw: 'សូមផ្ញើលេខកូដសម្ងាត់ OTP ជាបន្ទាន់ដើម្បីផ្ទៀងផ្ទាត់គណនី',
        normalizedText: 'សូមផ្ញើលេខកូដសម្ងាត់ OTP ជាបន្ទាន់ដើម្បីផ្ទៀងផ្ទាត់គណនី',
        detectedLanguage: 'km',
        extractedUrls: [],
        extractedPhoneNumbers: [],
      };

      const result = await textAnalysisDetector.detect(input, mockContext);
      expect(result).not.toBeNull();
      expect(result?.detector_name).toBe('text_linguistic_detector');
      expect(result?.score).toBeGreaterThan(40);
      expect(result?.evidence.indicators.length).toBeGreaterThan(0);
      expect(result?.confidence).toBeGreaterThanOrEqual(60);
    });

    it('scam_pattern_detector should detect crypto doubling scam pattern', async () => {
      const input: NormalizedInput = {
        type: 'TEXT',
        raw: 'Send 0.5 BTC and get 1.0 BTC back! Guaranteed 200% daily profit on smart contract.',
        normalizedText: 'Send 0.5 BTC and get 1.0 BTC back! Guaranteed 200% daily profit on smart contract.',
        detectedLanguage: 'en',
        extractedUrls: [],
        extractedPhoneNumbers: [],
      };

      const result = await scamPatternDetector.detect(input, mockContext);
      expect(result).not.toBeNull();
      expect(result?.detector_name).toBe('scam_pattern_detector');
      expect(result?.evidence.details?.categories).toContain('CRYPTO_SCAM');
      expect(result?.score).toBeGreaterThanOrEqual(40);
      expect(['medium', 'high', 'critical']).toContain(result?.severity);
    });

    it('url_security_detector should flag brand impersonation and suspicious paths', async () => {
      const input: NormalizedInput = {
        type: 'URL',
        raw: 'https://paypal-security-update-verify.com/login',
        normalizedUrl: 'https://paypal-security-update-verify.com/login',
        urlDomain: 'paypal-security-update-verify.com',
        extractedUrls: ['https://paypal-security-update-verify.com/login'],
        extractedPhoneNumbers: [],
      };

      const result = await urlAnalysisDetector.detect(input, mockContext);
      expect(result).not.toBeNull();
      expect(result?.detector_name).toBe('url_security_detector');
      expect(result?.score).toBeGreaterThan(30);
      expect(result?.evidence.indicators.length).toBeGreaterThan(0);
    });

    it('community_intelligence_detector should match previously confirmed scam reports', async () => {
      const input: NormalizedInput = {
        type: 'URL',
        raw: 'https://known-community-scam.xyz',
        normalizedUrl: 'https://known-community-scam.xyz',
        urlDomain: 'known-community-scam.xyz',
        extractedUrls: ['https://known-community-scam.xyz'],
        extractedPhoneNumbers: [],
      };

      const result = await communityReportDetector.detect(input, mockContext);
      expect(result).not.toBeNull();
      expect(result?.detector_name).toBe('community_intelligence_detector');
      expect(result?.score).toBeGreaterThan(0);
      expect(result?.evidence.details?.matched_reports_count).toBeGreaterThan(0);
    });
  });

  describe('3. Detector Registry & Pluggability', () => {
    it('should list all registered detectors and allow dynamic custom detector registration', () => {
      const initialDetectors = detectorRegistry.listDetectors();
      expect(initialDetectors.length).toBeGreaterThanOrEqual(7);

      const customDetector: IDetector = {
        name: 'custom_mock_detector',
        type: 'pattern',
        enabled: true,
        supports: (t: InputType) => t === 'TEXT',
        detect: async () => ({
          detector_name: 'custom_mock_detector',
          detector_type: 'pattern',
          score: 99,
          severity: 'critical',
          confidence: 99,
          evidence: {
            summary: 'Mock custom trigger fired',
            indicators: ['Flagged by mock detector'],
          },
          execution_time_ms: 1,
        }),
      };

      detectorRegistry.register(customDetector);
      expect(detectorRegistry.listDetectors().some((d) => d.name === 'custom_mock_detector')).toBe(true);

      // Clean up mock detector
      detectorRegistry.unregister('custom_mock_detector');
      expect(detectorRegistry.listDetectors().some((d) => d.name === 'custom_mock_detector')).toBe(false);
    });
  });

  describe('4. Centralized Risk Engine & Multi-Detector Correlation', () => {
    it('should boost risk and confidence when multiple independent detectors confirm threat', () => {
      const singleDetectorResult: DetectorResult = {
        detector_name: 'text_linguistic_detector',
        detector_type: 'text',
        score: 60,
        severity: 'high',
        confidence: 70,
        evidence: { summary: 'Urgency detected', indicators: ['Urgency'] },
        execution_time_ms: 5,
      };

      const secondDetectorResult: DetectorResult = {
        detector_name: 'scam_pattern_detector',
        detector_type: 'pattern',
        score: 75,
        severity: 'critical',
        confidence: 85,
        evidence: { summary: 'Crypto scam pattern matched', indicators: ['Crypto giveaway'] },
        execution_time_ms: 3,
      };

      // Single detector evaluation
      const singleRisk = riskEngine.evaluateEvidence({
        detectorResults: [singleDetectorResult],
        totalDetectorsRan: 1,
        maliciousCount: 0,
        suspiciousCount: 1,
        cleanCount: 0,
        indicators: ['Urgency'],
        detectedThreatCategories: ['SOCIAL_ENGINEERING'],
        highestSeverity: 'high',
      });

      // Correlated dual detector evaluation
      const correlatedRisk = riskEngine.evaluateEvidence({
        detectorResults: [singleDetectorResult, secondDetectorResult],
        totalDetectorsRan: 2,
        maliciousCount: 1,
        suspiciousCount: 1,
        cleanCount: 0,
        indicators: ['Urgency', 'Crypto giveaway'],
        detectedThreatCategories: ['SOCIAL_ENGINEERING', 'CRYPTO_SCAM'],
        highestSeverity: 'critical',
      });

      expect(correlatedRisk.riskScore).toBeGreaterThanOrEqual(singleRisk.riskScore);
      expect(correlatedRisk.confidenceScore).toBeGreaterThanOrEqual(singleRisk.confidenceScore);
      expect(['HIGH_RISK', 'MALICIOUS']).toContain(correlatedRisk.threatLevel);
    });
  });

  describe('5. Orchestrator End-to-End Execution', () => {
    it('detectionPipeline.execute should run full 8-stage pipeline for suspicious text', async () => {
      const res = await detectionPipeline.execute({
        type: 'TEXT',
        rawContent: 'Congratulations! You won $5,000 cash. Send your bank credentials to claim immediately!',
      });

      expect(res.status).toBe('COMPLETED');
      expect(res.id).toBeDefined();
      expect(res.risk_score).toBeGreaterThan(50);
      expect(res.detectors_evaluated.length).toBeGreaterThan(1);
      expect(res.detector_results.length).toBeGreaterThan(0);
      expect(res.signals.length).toBeGreaterThan(0);
      expect(res.recommended_actions.length).toBeGreaterThan(0);

      // Verify each detector returned structured format
      for (const det of res.detector_results) {
        expect(det.detector_name).toBeDefined();
        expect(typeof det.score).toBe('number');
        expect(['safe', 'low', 'medium', 'high', 'critical']).toContain(det.severity);
        expect(det.evidence).toBeDefined();
        expect(typeof det.confidence).toBe('number');
      }

      // Verify relational DB write
      const dbScan = await prisma.scan.findUnique({
        where: { id: res.id },
        include: { scanResult: true, detections: true },
      });
      expect(dbScan).not.toBeNull();
      expect(dbScan?.scanResult).not.toBeNull();
      expect(dbScan?.detections.length).toBeGreaterThan(0);
    });

    it('detectionPipeline.execute should handle clean conversational message without false positives', async () => {
      const res = await detectionPipeline.execute({
        type: 'TEXT',
        rawContent: 'Hello, could we schedule our project review meeting for tomorrow at 2 PM?',
      });

      expect(res.status).toBe('COMPLETED');
      expect(res.risk_score).toBeLessThan(30);
      expect(['SAFE', 'LOW_RISK']).toContain(res.threat_level);
      expect(res.safe_factors.length).toBeGreaterThan(0);
    });
  });
});
