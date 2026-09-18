import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const paymentFraudRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-PAY-001',
    category: 'payment_fraud',
    description: 'Demands for payment via untraceable gift cards or peer-to-peer overpayment tricks',
    severity: 'high',
    confidenceContribution: 65,
    version: '1.0.0',
    tags: ['payment_fraud', 'gift_card', 'overpayment'],
    patterns: [
      /\b(?:(?:pay|wire|send|refund)(?: it)?(?: back)? via (?:western union|moneygram|apple|steam|google play|razer gold|target)?\s*gift cards?|(?:apple|steam|google play|target) gift cards?|send photo of the back of the gift card)\b/i,
      /\b(?:(?:i )?accidentally sent (?:you )?(?:too much money|\$\d+.*via (?:zelle|venmo|cash app|aba))|refund.*via (?:zelle|venmo|cash app)|wire it back)\b/i,
    ],
    testCases: [
      {
        name: 'Gift card payment demand',
        input: { text: 'To clear your account penalty, you must pay via Google Play gift cards and send photo of the back.' },
        expectedMatch: true,
      },
      {
        name: 'Zelle accidental overpayment scam',
        input: { text: 'I accidentally sent you too much money on your payment, please refund the extra money via Zelle right now.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate payment notification',
        input: { text: 'Payment receipt: Your electricity bill of $45.20 was successfully paid via credit card.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-PAY-KM-001',
    category: 'payment_fraud',
    description: 'Untraceable card or payment voucher extortion in Khmer',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['payment_fraud', 'khmer', 'gift_card'],
    patterns: [
      /(?:ទិញកាតកោសដើម្បីទូទាត់|ផ្ញើលេខកូដកាតកោស|វេរប្រាក់លើសសូមផ្ញើត្រឡប់មកវិញ|កាត gift card)/,
    ],
    testCases: [
      {
        name: 'Khmer gift card extortion',
        input: { text: 'សូមទិញកាតកោសដើម្បីទូទាត់ប្រាក់ពិន័យ ហើយផ្ញើលេខកូដកាតកោសមកឱ្យខ្ញុំ' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer message',
        input: { text: 'ខ្ញុំបានទិញកាតទូរស័ព្ទបញ្ចូលរួចហើយ អរគុណច្រើន' },
        expectedMatch: false,
      },
    ],
  }),
];
