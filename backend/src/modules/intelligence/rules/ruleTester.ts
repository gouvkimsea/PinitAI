import { IScamRule, RuleTestReport, RuleTestCaseResult } from './types';
import { ruleRegistry } from './ruleRegistry';
import { logger } from '../../../utils/logger';

export class RuleTester {
  private static instance: RuleTester | null = null;

  private constructor() {}

  public static getInstance(): RuleTester {
    if (!RuleTester.instance) {
      RuleTester.instance = new RuleTester();
    }
    return RuleTester.instance;
  }

  /**
   * Runs all configured test cases for a single rule.
   */
  public async testRule(rule: IScamRule): Promise<RuleTestReport> {
    const startTime = Date.now();
    const testCases = rule.testCases || [];
    const results: RuleTestCaseResult[] = [];

    let passedTests = 0;

    for (const tc of testCases) {
      try {
        const detection = await rule.detect({
          text: tc.input.text || '',
          url: tc.input.url,
          qr: tc.input.qr,
          metadata: tc.input.metadata,
        });

        const actualMatch = detection.matched;
        const confidenceMatches =
          !tc.minConfidence || detection.confidence >= tc.minConfidence;
        const passed = actualMatch === tc.expectedMatch && confidenceMatches;

        if (passed) passedTests++;

        results.push({
          testName: tc.name,
          passed,
          expectedMatch: tc.expectedMatch,
          actualMatch,
          actualConfidence: detection.confidence,
        });
      } catch (err: any) {
        results.push({
          testName: tc.name,
          passed: false,
          expectedMatch: tc.expectedMatch,
          actualMatch: false,
          actualConfidence: 0,
          error: err?.message || String(err),
        });
      }
    }

    const durationMs = Date.now() - startTime;
    const allPassed = results.length > 0 && passedTests === results.length;

    return {
      ruleId: rule.id,
      version: rule.version,
      passed: testCases.length === 0 ? true : allPassed,
      totalTests: testCases.length,
      passedTests,
      failedTests: testCases.length - passedTests,
      results,
      durationMs,
    };
  }

  /**
   * Tests a registered rule by ID.
   */
  public async testRuleById(ruleId: string): Promise<RuleTestReport | null> {
    const rule = ruleRegistry.getRule(ruleId);
    if (!rule) return null;
    return this.testRule(rule);
  }

  /**
   * Executes test suites across all registered rules.
   */
  public async testAllRegisteredRules(): Promise<{
    passed: boolean;
    totalRules: number;
    passedRules: number;
    failedRules: number;
    reports: RuleTestReport[];
    durationMs: number;
  }> {
    const startTime = Date.now();
    const rules = ruleRegistry.getAllRules();
    const reports: RuleTestReport[] = [];

    let passedRules = 0;

    for (const rule of rules) {
      const report = await this.testRule(rule);
      reports.push(report);
      if (report.passed) {
        passedRules++;
      } else {
        logger.warn(`Rule test suite failed for [${rule.id}] v${rule.version}`, {
          failedTests: report.failedTests,
        });
      }
    }

    const durationMs = Date.now() - startTime;

    return {
      passed: passedRules === rules.length,
      totalRules: rules.length,
      passedRules,
      failedRules: rules.length - passedRules,
      reports,
      durationMs,
    };
  }
}

export const ruleTester = RuleTester.getInstance();
