import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const loanScamsRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-LOAN-001',
    category: 'loan_scams',
    description: 'Guaranteed instant loan with no credit check requiring upfront collateral/insurance payment',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['loan_scams', 'instant_loan', 'no_credit_check'],
    patterns: [
      /\b(?:instant (?:cash )?loans?.*no credit (?:score )?check|guaranteed loan up to \$[\d,]+|100% approval(?: rate)?|no credit score check)\b/i,
      /\b(?:(?:pay |upfront )?(?:loan )?insurance (?:fee|deposit)(?: of \$[\d,]+)? before (?:fund )?disbursement|advance processing deposit required to release loan|collateral deposit via bank transfer before loan)\b/i,
    ],
    testCases: [
      {
        name: 'Instant bad credit loan approval lure',
        input: { text: 'Need cash fast? Instant loan approved with no credit check up to $50,000 guaranteed today.' },
        expectedMatch: true,
      },
      {
        name: 'Upfront loan insurance fee requirement',
        input: { text: 'Your loan is approved, pay loan insurance fee before disbursement of $150 to finalize transfer.' },
        expectedMatch: true,
      },
      {
        name: 'Bank mortgage information',
        input: { text: 'Mortgage loan applications require income verification, credit history check, and property appraisal.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-LOAN-KM-001',
    category: 'loan_scams',
    description: 'Online fast loan scams without collateral in Khmer',
    severity: 'high',
    confidenceContribution: 75,
    version: '1.0.0',
    tags: ['loan_scams', 'khmer', 'fast_loan'],
    patterns: [
      /(?:កម្ចីប្រាក់រហ័សមិនបាច់មានទ្រព្យបញ្ចាំ|អនុម័តកម្ចី ១០០% ក្នុងរយៈពេល ៥ នាទី|បង់ប្រាក់កក់សេវាកម្ចីមុន|កម្ចីអនឡាញការប្រាក់ទាប)/,
    ],
    testCases: [
      {
        name: 'Khmer fast loan no collateral scam',
        input: { text: 'សេវាកម្មកម្ចីប្រាក់រហ័សមិនបាច់មានទ្រព្យបញ្ចាំ អនុម័តកម្ចី ១០០% ក្នុងរយៈពេល ៥ នាទី' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer bank loan details',
        input: { text: 'អតិថិជនស្នើសុំឥណទានផ្ទះត្រូវភ្ជាប់ជាមួយលិខិតបញ្ជាក់ប្រាក់ខែ' },
        expectedMatch: false,
      },
    ],
  }),
];
