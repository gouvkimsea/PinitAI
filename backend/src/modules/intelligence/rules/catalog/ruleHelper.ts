import { IScamRule, RuleCategory, RuleSeverity, RuleTestCase, RuleEvaluationContext, RuleDetectionResult } from '../types';

export interface PatternRuleConfig {
  id: string;
  category: RuleCategory;
  description: string;
  severity: RuleSeverity;
  version?: string;
  enabled?: boolean;
  confidenceContribution: number;
  tags?: string[];
  patterns: RegExp[];
  testCases?: RuleTestCase[];
  customFilter?: (context: RuleEvaluationContext) => boolean;
}

export function createPatternRule(config: PatternRuleConfig): IScamRule {
  const version = config.version || '1.0.0';
  const enabled = config.enabled ?? true;

  return {
    id: config.id,
    category: config.category,
    description: config.description,
    severity: config.severity,
    version,
    enabled,
    confidenceContribution: config.confidenceContribution,
    tags: config.tags || [],
    testCases: config.testCases || [],
    detect: (context: RuleEvaluationContext): RuleDetectionResult => {
      if (config.customFilter && !config.customFilter(context)) {
        return { matched: false, confidence: 0 };
      }

      const combinedText = `${context.text || ''} ${context.normalizedText || ''} ${context.url || ''} ${context.qr || ''}`;
      if (!combinedText.trim()) {
        return { matched: false, confidence: 0 };
      }

      const matchedSnippets: string[] = [];
      const matchedPatterns: string[] = [];

      for (const pattern of config.patterns) {
        const match = pattern.exec(combinedText);
        if (match) {
          matchedPatterns.push(pattern.source);
          matchedSnippets.push(match[0]);
        }
      }

      if (matchedSnippets.length === 0) {
        return { matched: false, confidence: 0 };
      }

      return {
        matched: true,
        confidence: config.confidenceContribution,
        evidence: {
          ruleId: config.id,
          category: config.category,
          description: config.description,
          severity: config.severity,
          confidenceContribution: config.confidenceContribution,
          matchedPatterns,
          snippets: Array.from(new Set(matchedSnippets)).slice(0, 5),
        },
      };
    },
    explain: (result: RuleDetectionResult): string => {
      if (!result.matched || !result.evidence) return '';
      return `Rule [${config.id}] flagged ${config.category} (${config.severity} severity): ${config.description}. Matched: "${result.evidence.snippets.join(', ')}".`;
    },
  };
}
