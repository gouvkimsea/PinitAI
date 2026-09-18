import { IScamRule, RuleCategory, RuleSeverity } from './types';
import { DEFAULT_MODULAR_RULES } from './catalog';
import { logger } from '../../../utils/logger';

export interface RuleVersionRecord {
  version: string;
  updatedAt: Date;
  ruleSnapshot: IScamRule;
  changeNote?: string;
}

export class RuleRegistry {
  private static instance: RuleRegistry | null = null;
  private rules: Map<string, IScamRule> = new Map();
  private versionHistory: Map<string, RuleVersionRecord[]> = new Map();

  private constructor() {
    this.resetToDefaults();
  }

  public static getInstance(): RuleRegistry {
    if (!RuleRegistry.instance) {
      RuleRegistry.instance = new RuleRegistry();
    }
    return RuleRegistry.instance;
  }

  /**
   * Resets registry to the default built-in catalog of modular rules.
   */
  public resetToDefaults(): void {
    this.rules.clear();
    this.versionHistory.clear();

    for (const rule of DEFAULT_MODULAR_RULES) {
      this.registerRule(rule, true);
    }
    logger.info('RuleRegistry initialized with default catalog', { count: this.rules.size });
  }

  /**
   * Registers a new rule or hot-updates an existing one.
   */
  public registerRule(rule: IScamRule, updateIfExists = false, changeNote?: string): boolean {
    const existing = this.rules.get(rule.id);
    if (existing && !updateIfExists) {
      logger.warn(`Rule [${rule.id}] already exists and updateIfExists is false`);
      return false;
    }

    // Save previous version in history if updating
    if (existing) {
      const history = this.versionHistory.get(rule.id) || [];
      history.push({
        version: existing.version,
        updatedAt: new Date(),
        ruleSnapshot: { ...existing },
        changeNote: changeNote || `Updated to version ${rule.version}`,
      });
      this.versionHistory.set(rule.id, history);
    }

    this.rules.set(rule.id, rule);
    logger.debug(`Registered rule [${rule.id}] v${rule.version} (${rule.category})`);
    return true;
  }

  /**
   * Unregisters a rule by ID.
   */
  public unregisterRule(ruleId: string): boolean {
    return this.rules.delete(ruleId);
  }

  /**
   * Retrieves a rule by ID.
   */
  public getRule(ruleId: string): IScamRule | undefined {
    return this.rules.get(ruleId);
  }

  /**
   * Retrieves all registered rules with optional filtering.
   */
  public getAllRules(filters?: {
    category?: RuleCategory;
    enabledOnly?: boolean;
    severity?: RuleSeverity;
    search?: string;
  }): IScamRule[] {
    let result = Array.from(this.rules.values());

    if (filters?.category) {
      result = result.filter((r) => r.category === filters.category);
    }

    if (filters?.enabledOnly) {
      result = result.filter((r) => r.enabled);
    }

    if (filters?.severity) {
      result = result.filter((r) => r.severity === filters.severity);
    }

    if (filters?.search) {
      const term = filters.search.toLowerCase();
      result = result.filter(
        (r) =>
          r.id.toLowerCase().includes(term) ||
          r.description.toLowerCase().includes(term) ||
          r.category.toLowerCase().includes(term) ||
          (r.tags && r.tags.some((t) => t.toLowerCase().includes(term)))
      );
    }

    return result;
  }

  /**
   * Enables or disables a rule at runtime without rewriting code or restarting.
   */
  public setRuleEnabled(ruleId: string, enabled: boolean): boolean {
    const rule = this.rules.get(ruleId);
    if (!rule) return false;
    rule.enabled = enabled;
    logger.info(`Rule [${ruleId}] enabled status set to ${enabled}`);
    return true;
  }

  /**
   * Hot-updates a rule's version and properties at runtime.
   */
  public updateRule(ruleId: string, updates: Partial<IScamRule>, changeNote?: string): IScamRule | null {
    const current = this.rules.get(ruleId);
    if (!current) return null;

    const history = this.versionHistory.get(ruleId) || [];
    history.push({
      version: current.version,
      updatedAt: new Date(),
      ruleSnapshot: { ...current },
      changeNote: changeNote || `Updated rule properties`,
    });
    this.versionHistory.set(ruleId, history);

    const updated: IScamRule = {
      ...current,
      ...updates,
      id: current.id, // Immutable ID
    };

    this.rules.set(ruleId, updated);
    logger.info(`Rule [${ruleId}] successfully updated to v${updated.version}`);
    return updated;
  }

  /**
   * Returns audit version history for a given rule.
   */
  public getVersionHistory(ruleId: string): RuleVersionRecord[] {
    return this.versionHistory.get(ruleId) || [];
  }

  /**
   * Returns summary counts and category distributions.
   */
  public getRuleStats(): {
    total: number;
    enabled: number;
    disabled: number;
    byCategory: Record<string, number>;
  } {
    const all = Array.from(this.rules.values());
    const byCategory: Record<string, number> = {};

    for (const r of all) {
      byCategory[r.category] = (byCategory[r.category] || 0) + 1;
    }

    return {
      total: all.length,
      enabled: all.filter((r) => r.enabled).length,
      disabled: all.filter((r) => !r.enabled).length,
      byCategory,
    };
  }
}

export const ruleRegistry = RuleRegistry.getInstance();
