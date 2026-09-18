import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const fakeInvestmentRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-INVEST-001',
    category: 'fake_investment',
    description: 'Guaranteed risk-free high yield investment or Ponzi scheme lure',
    severity: 'critical',
    confidenceContribution: 75,
    version: '1.0.0',
    tags: ['fake_investment', 'ponzi', 'high_yield'],
    patterns: [
      /\b(?:guaranteed (?:daily|weekly|monthly|\d+%)|risk-free (?:high yield|investment|arbitrage)|(?:\d+%) returns guaranteed|vip investment tier|without risk|\d+% daily)\b/i,
      /\b(?:automated trading bot|deposit \$[1-9]\d{1,3} earn|smart crypto trading bot|passive income guaranteed with zero risk|crypto_wealth_advisor)\b/i,
    ],
    testCases: [
      {
        name: 'Guaranteed profit lure',
        input: { text: 'Join our exclusive VIP group: 100% returns guaranteed daily with risk-free high yield AI trading.' },
        expectedMatch: true,
      },
      {
        name: 'Deposit multiplier lure',
        input: { text: 'Special offer: deposit $100 earn $1000 today instantly via our automated trading bot.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate investment discussion',
        input: { text: 'Past market performance does not guarantee future results. Diversification carries market risk.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-INVEST-KM-001',
    category: 'fake_investment',
    description: 'High-yield fake investment and Ponzi lures in Khmer',
    severity: 'critical',
    confidenceContribution: 80,
    version: '1.0.0',
    tags: ['fake_investment', 'khmer', 'ponzi'],
    patterns: [
      /(?:ធានាចំណេញ\s*\d+%|ធានាចំណេញ|វិនិយោគចំណេញខ្ពស់|ប្រាក់ចំណេញធានា|ដាក់ប្រាក់ចំណេញទ្វេដង|គ្មានហានិភ័យ|ឱកាសវិនិយោគពិសេស)/,
    ],
    testCases: [
      {
        name: 'Khmer high-yield investment scheme',
        input: { text: 'គម្រោងវិនិយោគចំណេញខ្ពស់ ធានាចំណេញ១០០% គ្មានហានិភ័យឡើយ' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer economic report',
        input: { text: 'អត្រាការប្រាក់បញ្ញើនៅធនាគារមានការប្រែប្រួលតាមទីផ្សារ' },
        expectedMatch: false,
      },
    ],
  }),
];
