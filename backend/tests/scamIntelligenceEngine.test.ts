import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import {
  ruleRegistry,
  ruleTester,
  ruleLogger,
  feedbackTracker,
  scamIntelligenceEngine,
  verifyCatalogCoverage,
  ALL_RULE_CATEGORIES,
  CATEGORY_DISPLAY_NAMES,
  normalizeCategory,
  IScamRule,
} from '../src/modules/intelligence';
import { createPatternRule } from '../src/modules/intelligence/rules/catalog/ruleHelper';

const app = createApp();

describe('Scam Intelligence Engine (Modular Rules System)', () => {
  beforeEach(() => {
    ruleRegistry.resetToDefaults();
    feedbackTracker.reset();
    ruleLogger.clearLogs();
  });

  // =========================================================================
  // 1. Mandatory 20 Categories Coverage & Rule Schema
  // =========================================================================
  describe('1. Categories Coverage & Rule Schema', () => {
    it('covers all 20 required scam categories in the catalog', () => {
      const { covered, missingCategories } = verifyCatalogCoverage();
      expect(covered).toBe(true);
      expect(missingCategories).toHaveLength(0);

      // Verify all 20 categories exist in ALL_RULE_CATEGORIES
      expect(ALL_RULE_CATEGORIES).toHaveLength(20);
      expect(ALL_RULE_CATEGORIES).toEqual(
        expect.arrayContaining([
          'phishing',
          'impersonation',
          'financial_fraud',
          'payment_fraud',
          'credential_theft',
          'otp_theft',
          'social_engineering',
          'fake_employment',
          'fake_investment',
          'fake_shopping',
          'fake_delivery',
          'fake_support',
          'romance_scams',
          'giveaway_scams',
          'loan_scams',
          'crypto_scams',
          'account_takeover',
          'malware_delivery',
          'malicious_downloads',
          'qr_scams',
        ])
      );
    });

    it('every rule adheres to the required schema attributes', () => {
      const allRules = ruleRegistry.getAllRules();
      expect(allRules.length).toBeGreaterThanOrEqual(20);

      for (const rule of allRules) {
        // 1. rule ID
        expect(rule.id).toBeDefined();
        expect(typeof rule.id).toBe('string');
        expect(rule.id.length).toBeGreaterThan(3);

        // 2. category (one of the 20)
        expect(ALL_RULE_CATEGORIES).toContain(rule.category);

        // 3. description
        expect(rule.description).toBeDefined();
        expect(rule.description.length).toBeGreaterThan(10);

        // 4. severity
        expect(['low', 'medium', 'high', 'critical']).toContain(rule.severity);

        // 5. detection logic
        expect(typeof rule.detect).toBe('function');

        // 6. confidence contribution
        expect(rule.confidenceContribution).toBeGreaterThan(0);
        expect(rule.confidenceContribution).toBeLessThanOrEqual(100);

        // 7. version
        expect(rule.version).toMatch(/^\d+\.\d+\.\d+$/);

        // 8. enabled/disabled state
        expect(typeof rule.enabled).toBe('boolean');

        // 9. evidence generation capability
        expect(typeof rule.explain).toBe('function');
      }
    });

    it('correctly normalizes category aliases and display names', () => {
      expect(normalizeCategory('financial fraud')).toBe('financial_fraud');
      expect(normalizeCategory('OTP THEFT')).toBe('otp_theft');
      expect(normalizeCategory('quishing')).toBe('qr_scams');
      expect(normalizeCategory('tech support')).toBe('fake_support');
      expect(CATEGORY_DISPLAY_NAMES['phishing']).toBe('Phishing');
      expect(CATEGORY_DISPLAY_NAMES['qr_scams']).toBe('QR Scams');
    });
  });

  // =========================================================================
  // 2. Rule Testing Harness
  // =========================================================================
  describe('2. Rule Self-Testing Harness', () => {
    it('executes self-testing fixtures across all registered rules with 100% pass rate', async () => {
      const testReport = await ruleTester.testAllRegisteredRules();
      const failedFixtures = testReport.reports
        .filter((r) => !r.passed)
        .map((r) => ({ id: r.ruleId, fails: r.results.filter((x) => !x.passed) }));
      expect(failedFixtures).toEqual([]);
      expect(testReport.passed).toBe(true);
      expect(testReport.failedRules).toBe(0);
      expect(testReport.passedRules).toBe(testReport.totalRules);
      expect(testReport.durationMs).toBeGreaterThanOrEqual(0);
    });

    it('individual rule testing returns granular positive & negative test fixture results', async () => {
      const phishReport = await ruleTester.testRuleById('RULE-PHISH-001');
      expect(phishReport).not.toBeNull();
      expect(phishReport?.passed).toBe(true);
      expect(phishReport?.totalTests).toBeGreaterThanOrEqual(2);
      expect(phishReport?.results.every((r) => r.passed)).toBe(true);
    });

    it('flags test failure if a rule fails its expected behavior', async () => {
      const faultyRule: IScamRule = {
        id: 'RULE-FAULTY-001',
        category: 'phishing',
        description: 'Faulty rule that fails test case',
        severity: 'low',
        version: '1.0.0',
        enabled: true,
        confidenceContribution: 20,
        detect: () => ({ matched: false, confidence: 0 }), // always false
        testCases: [
          {
            name: 'Positive test that expects match',
            input: { text: 'should match this' },
            expectedMatch: true, // will fail
          },
        ],
      };

      const report = await ruleTester.testRule(faultyRule);
      expect(report.passed).toBe(false);
      expect(report.failedTests).toBe(1);
    });
  });

  // =========================================================================
  // 3. Rule Versioning & Hot-Updating
  // =========================================================================
  describe('3. Rule Versioning & Hot-Updating', () => {
    it('allows updating rule version and keeps complete audit history', () => {
      const initialRule = ruleRegistry.getRule('RULE-PHISH-001');
      expect(initialRule?.version).toBe('1.0.0');

      const updated = ruleRegistry.updateRule(
        'RULE-PHISH-001',
        {
          version: '1.1.0',
          description: 'Updated phishing lure detector with enhanced heuristics',
          confidenceContribution: 72,
        },
        'Upgraded heuristics based on threat intel feed'
      );

      expect(updated).not.toBeNull();
      expect(updated?.version).toBe('1.1.0');
      expect(updated?.confidenceContribution).toBe(72);

      const history = ruleRegistry.getVersionHistory('RULE-PHISH-001');
      expect(history.length).toBe(1);
      expect(history[0].version).toBe('1.0.0');
      expect(history[0].changeNote).toContain('threat intel');
    });

    it('can dynamically register new rules without engine restarts', async () => {
      const newCustomRule = createPatternRule({
        id: 'RULE-CUSTOM-999',
        category: 'fake_investment',
        description: 'Emerging crypto bot pump-and-dump scheme',
        severity: 'high',
        version: '1.0.0',
        confidenceContribution: 68,
        patterns: [/moonshot 1000x guaranteed pump/i],
        testCases: [
          {
            name: 'Moonshot pump pattern',
            input: { text: 'Join our VIP channel for moonshot 1000x guaranteed pump!' },
            expectedMatch: true,
          },
        ],
      });

      const registered = ruleRegistry.registerRule(newCustomRule);
      expect(registered).toBe(true);

      const retrieved = ruleRegistry.getRule('RULE-CUSTOM-999');
      expect(retrieved).toBeDefined();

      const testRes = await ruleTester.testRule(newCustomRule);
      expect(testRes.passed).toBe(true);
    });
  });

  // =========================================================================
  // 4. Runtime Enable/Disable Toggle
  // =========================================================================
  describe('4. Runtime Enable/Disable Toggle', () => {
    it('disables a rule so it is excluded from evaluation without restart', async () => {
      const sampleText = 'Special offer: deposit $100 earn $1000 today instantly via our automated trading bot.';

      // Before disabling: rule matches
      const beforeVerdict = await scamIntelligenceEngine.evaluate({ text: sampleText });
      expect(beforeVerdict.triggeredRules.some((r) => r.ruleId === 'RULE-INVEST-001')).toBe(true);

      // Disable rule
      const toggled = ruleRegistry.setRuleEnabled('RULE-INVEST-001', false);
      expect(toggled).toBe(true);

      // After disabling: rule should NOT fire
      const afterVerdict = await scamIntelligenceEngine.evaluate({ text: sampleText });
      expect(afterVerdict.triggeredRules.some((r) => r.ruleId === 'RULE-INVEST-001')).toBe(false);

      // Re-enable
      ruleRegistry.setRuleEnabled('RULE-INVEST-001', true);
      const reEnabledVerdict = await scamIntelligenceEngine.evaluate({ text: sampleText });
      expect(reEnabledVerdict.triggeredRules.some((r) => r.ruleId === 'RULE-INVEST-001')).toBe(true);
    });
  });

  // =========================================================================
  // 5. False-Positive, False-Negative & Performance Telemetry
  // =========================================================================
  describe('5. False-Positive, False-Negative & Metrics Tracking', () => {
    it('tracks evaluation telemetry and calculates precision metrics', async () => {
      await scamIntelligenceEngine.evaluate({
        text: 'Alert: Click here to verify your account immediately or access will be revoked.',
      });

      const metrics = feedbackTracker.getRuleMetrics('RULE-PHISH-001');
      expect(metrics).not.toBeNull();
      expect(metrics?.evaluationsCount).toBeGreaterThanOrEqual(1);
      expect(metrics?.matchCount).toBeGreaterThanOrEqual(1);
      expect(metrics?.precision).toBe(100);
    });

    it('records false-positives and recalculates empirical precision', () => {
      feedbackTracker.recordExecution('RULE-PHISH-001', true, 5);
      feedbackTracker.recordExecution('RULE-PHISH-001', true, 6);

      // Record a false positive report
      const fpRecord = feedbackTracker.recordFalsePositive(
        'RULE-PHISH-001',
        'Benign password reset email from our internal intranet',
        'Legitimate internal IT system flagged incorrectly',
        'security_officer_1'
      );

      expect(fpRecord.id).toBeDefined();
      expect(fpRecord.type).toBe('false_positive');

      const metrics = feedbackTracker.getRuleMetrics('RULE-PHISH-001');
      expect(metrics?.falsePositivesCount).toBe(1);
      expect(metrics?.precision).toBe(50); // 1 true positive out of 2 matches
    });

    it('records false-negatives and tracks missed detections', () => {
      const fnRecord = feedbackTracker.recordFalseNegative(
        'RULE-OTP-001',
        'Novel stealth phrasing: relay the mobile security token to our voice operator',
        'Novel evasion tactic not captured by regex',
        'qa_engineer'
      );

      expect(fnRecord.id).toBeDefined();
      expect(fnRecord.type).toBe('false_negative');

      const records = feedbackTracker.getFeedbackRecords({ ruleId: 'RULE-OTP-001' });
      expect(records).toHaveLength(1);
    });

    it('rule logger maintains recent evaluation traces in ring buffer', async () => {
      await scamIntelligenceEngine.evaluate({
        text: 'Please install AnyDesk to allow technician access to clean virus',
      });

      const logs = ruleLogger.getRecentLogs(10);
      expect(logs.length).toBeGreaterThanOrEqual(1);
      expect(logs[0].matchedRulesCount).toBeGreaterThan(0);
      expect(logs[0].traces.some((t) => t.matched)).toBe(true);
    });
  });

  // =========================================================================
  // 6. Anti-Unilateral Principle & Multi-Signal Aggregation
  // =========================================================================
  describe('6. Anti-Unilateral Principle & Multi-Signal Aggregation', () => {
    it('anti-unilateral: single weak rule CANNOT classify content as a scam', async () => {
      // Register a temporary weak rule (severity low, confidence 20)
      const weakRule = createPatternRule({
        id: 'RULE-WEAK-TEST',
        category: 'social_engineering',
        description: 'Generic urgency phrase used in both marketing and fraud',
        severity: 'low',
        confidenceContribution: 20,
        patterns: [/limited time offer act fast/i],
      });
      ruleRegistry.registerRule(weakRule, true);

      const verdict = await scamIntelligenceEngine.evaluate({
        text: 'Hello, this is a limited time offer act fast to save 10% on groceries.',
      });

      // Strict Anti-Unilateral assertions:
      expect(verdict.isSingleWeakRule).toBe(true);
      expect(verdict.isScam).toBe(false);
      expect(verdict.threatLevel).toBe('LOW');
      expect(verdict.scamScore).toBeLessThanOrEqual(25);
      expect(verdict.explanation).toContain('Under the Anti-Unilateral Principle');
    });

    it('multi-signal correlation: combines multiple independent signals to classify scam', async () => {
      // Content containing 3 independent scam categories:
      // 1. Impersonation: "official notice from national bank"
      // 2. OTP theft: "send the 6-digit OTP code"
      // 3. Phishing: "verify your account immediately"
      const multiSignalText =
        'Official notice from national bank: Your ABA Bank account is suspended! Click here to verify your account immediately and send the 6-digit OTP code to unlock.';

      const verdict = await scamIntelligenceEngine.evaluate({ text: multiSignalText });

      expect(verdict.isScam).toBe(true);
      expect(verdict.threatLevel).toBe('MALICIOUS');
      expect(verdict.scamScore).toBeGreaterThanOrEqual(75);
      expect(verdict.categoryCount).toBeGreaterThanOrEqual(2);
      expect(verdict.signalsBreakdown.correlationMultiplier).toBeGreaterThan(1.0);
      expect(verdict.explanation).toContain('Multi-signal scam detected');
      expect(verdict.triggeredRules.length).toBeGreaterThanOrEqual(2);
    });

    it('clean content triggers zero rules and returns CLEAN', async () => {
      const cleanVerdict = await scamIntelligenceEngine.evaluate({
        text: 'Hi Alice, let us meet tomorrow at 10 AM in the second floor meeting room for project planning.',
      });

      expect(cleanVerdict.isScam).toBe(false);
      expect(cleanVerdict.threatLevel).toBe('CLEAN');
      expect(cleanVerdict.scamScore).toBe(0);
      expect(cleanVerdict.triggeredRules).toHaveLength(0);
    });
  });

  // =========================================================================
  // 7. HTTP API Integration Endpoints
  // =========================================================================
  describe('7. HTTP API Integration', () => {
    it('GET /api/intelligence/rules should return list of rules and category stats', async () => {
      const res = await request(app).get('/api/intelligence/rules');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.total).toBeGreaterThanOrEqual(20);
      expect(res.body.stats.total).toBeGreaterThanOrEqual(20);
      expect(res.body.data[0]).toHaveProperty('id');
      expect(res.body.data[0]).toHaveProperty('category');
      expect(res.body.data[0]).toHaveProperty('severity');
    });

    it('GET /api/intelligence/rules/:id should return single rule details and metrics', async () => {
      const res = await request(app).get('/api/intelligence/rules/RULE-PHISH-001');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe('RULE-PHISH-001');
      expect(res.body.data.category).toBe('phishing');
    });

    it('GET /api/intelligence/metrics should return telemetry and FP/FN summary', async () => {
      const res = await request(app).get('/api/intelligence/metrics');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.summary).toBeDefined();
      expect(Array.isArray(res.body.rule_metrics)).toBe(true);
    });

    it('POST /api/intelligence/feedback/false-positive should record report', async () => {
      const res = await request(app)
        .post('/api/intelligence/feedback/false-positive')
        .send({
          rule_id: 'RULE-PHISH-001',
          sample_content: 'Internal verification link for intranet',
          reason: 'Internal test message',
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.type).toBe('false_positive');
    });

    it('POST /api/intelligence/feedback/false-negative should record report', async () => {
      const res = await request(app)
        .post('/api/intelligence/feedback/false-negative')
        .send({
          rule_id: 'RULE-CRYPTO-001',
          sample_content: 'Stealth obfuscated seed phrase prompt',
          reason: 'Bypassed current regex',
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.type).toBe('false_negative');
    });

    it('POST /api/intelligence/evaluate should evaluate content using modular engine', async () => {
      const res = await request(app)
        .post('/api/intelligence/evaluate')
        .send({
          text: 'Send 1 ETH get 2 back automatically! Also enter your 12-word seed phrase.',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.isScam).toBe(true);
      expect(res.body.data.categoriesDetected).toContain('crypto_scams');
    });
  });
});
