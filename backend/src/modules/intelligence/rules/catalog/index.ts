import { IScamRule, RuleCategory, ALL_RULE_CATEGORIES } from '../types';
import { phishingRules } from './phishing';
import { impersonationRules } from './impersonation';
import { financialFraudRules } from './financialFraud';
import { paymentFraudRules } from './paymentFraud';
import { credentialTheftRules } from './credentialTheft';
import { otpTheftRules } from './otpTheft';
import { socialEngineeringRules } from './socialEngineering';
import { fakeEmploymentRules } from './fakeEmployment';
import { fakeInvestmentRules } from './fakeInvestment';
import { fakeShoppingRules } from './fakeShopping';
import { fakeDeliveryRules } from './fakeDelivery';
import { fakeSupportRules } from './fakeSupport';
import { romanceScamsRules } from './romanceScams';
import { giveawayScamsRules } from './giveawayScams';
import { loanScamsRules } from './loanScams';
import { cryptoScamsRules } from './cryptoScams';
import { accountTakeoverRules } from './accountTakeover';
import { malwareDeliveryRules } from './malwareDelivery';
import { maliciousDownloadsRules } from './maliciousDownloads';
import { qrScamsRules } from './qrScams';

export const DEFAULT_MODULAR_RULES: IScamRule[] = [
  ...phishingRules,
  ...impersonationRules,
  ...financialFraudRules,
  ...paymentFraudRules,
  ...credentialTheftRules,
  ...otpTheftRules,
  ...socialEngineeringRules,
  ...fakeEmploymentRules,
  ...fakeInvestmentRules,
  ...fakeShoppingRules,
  ...fakeDeliveryRules,
  ...fakeSupportRules,
  ...romanceScamsRules,
  ...giveawayScamsRules,
  ...loanScamsRules,
  ...cryptoScamsRules,
  ...accountTakeoverRules,
  ...malwareDeliveryRules,
  ...maliciousDownloadsRules,
  ...qrScamsRules,
];

/**
 * Validates that all 20 required categories have at least one active rule in the catalog.
 */
export function verifyCatalogCoverage(): { covered: boolean; missingCategories: RuleCategory[] } {
  const presentCategories = new Set<RuleCategory>(DEFAULT_MODULAR_RULES.map((r) => r.category));
  const missingCategories = ALL_RULE_CATEGORIES.filter((cat) => !presentCategories.has(cat));
  return {
    covered: missingCategories.length === 0,
    missingCategories,
  };
}

export {
  phishingRules,
  impersonationRules,
  financialFraudRules,
  paymentFraudRules,
  credentialTheftRules,
  otpTheftRules,
  socialEngineeringRules,
  fakeEmploymentRules,
  fakeInvestmentRules,
  fakeShoppingRules,
  fakeDeliveryRules,
  fakeSupportRules,
  romanceScamsRules,
  giveawayScamsRules,
  loanScamsRules,
  cryptoScamsRules,
  accountTakeoverRules,
  malwareDeliveryRules,
  maliciousDownloadsRules,
  qrScamsRules,
};
