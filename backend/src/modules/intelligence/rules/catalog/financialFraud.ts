import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const financialFraudRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-FIN-001',
    category: 'financial_fraud',
    description: 'Advance fee fraud, fake inheritance, or unverified wire transfer demands',
    severity: 'high',
    confidenceContribution: 65,
    version: '1.0.0',
    tags: ['financial_fraud', 'advance_fee', 'wire_transfer'],
    patterns: [
      /\b(?:advance fee required to release funds|pay a clearance fee of \$?\d+|unclaimed inheritance of \$[\d,]+|wire transfer fee upfront)\b/i,
      /\b(?:deposit this check and return the difference|overpayment check refund|consignment box release fee)\b/i,
    ],
    testCases: [
      {
        name: 'Advance fee clearance lure',
        input: { text: 'You have won $500,000, but an advance fee required to release funds of $250 must be sent.' },
        expectedMatch: true,
      },
      {
        name: 'Overpayment check scam lure',
        input: { text: 'Please deposit this check and return the difference via Western Union immediately.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate financial advisory',
        input: { text: 'Your monthly bank statement is available for download in the secure portal.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-FIN-KM-001',
    category: 'financial_fraud',
    description: 'Advance fee and wire transfer fraud in Khmer',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['financial_fraud', 'khmer', 'advance_fee'],
    patterns: [
      /(?:បង់ថ្លៃសេវាដោះលែងប្រាក់|ផ្ញើប្រាក់កក់មុនដើម្បីទទួលប្រាក់|មរតកដែលមិនទាន់បើក|បង់ថ្លៃធានារ៉ាប់រងប្រាក់កម្ចីមុន)/,
    ],
    testCases: [
      {
        name: 'Khmer advance fee lure',
        input: { text: 'សូមបង់ថ្លៃសេវាដោះលែងប្រាក់ចំនួន $100 ជាមុនសិនដើម្បីទទួលបានរង្វាន់' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer text',
        input: { text: 'ថ្លៃសេវាធនាគារប្រចាំខែគឺ ១ ដុល្លារ' },
        expectedMatch: false,
      },
    ],
  }),
];
