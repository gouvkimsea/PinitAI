import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const fakeDeliveryRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-DELIV-001',
    category: 'fake_delivery',
    description: 'Fake parcel delivery issue, unpaid redelivery fee, or address update lure',
    severity: 'high',
    confidenceContribution: 65,
    version: '1.0.0',
    tags: ['fake_delivery', 'package', 'redelivery'],
    patterns: [
      /\b(?:your parcel cannot be delivered due to (?:incomplete address|unpaid customs fee)|package delivery suspended|pay \$(?:1|2|3|4|5) redelivery fee)\b/i,
      /\b(?:update your shipping address within 24 hours to receive package|usps parcel pending redelivery confirmation)\b/i,
    ],
    testCases: [
      {
        name: 'Unpaid redelivery fee lure',
        input: { text: 'Your parcel cannot be delivered due to incomplete address. Please pay $2.99 redelivery fee to reschedule.' },
        expectedMatch: true,
      },
      {
        name: 'USPS package suspended lure',
        input: { text: 'USPS Notice: Package delivery suspended. Update your shipping address within 24 hours to receive package.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate tracking confirmation',
        input: { text: 'Your order has shipped via FedEx. Expected delivery is Tuesday by end of day.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-DELIV-KM-001',
    category: 'fake_delivery',
    description: 'Fake postal and package delivery alerts in Khmer',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['fake_delivery', 'khmer', 'package'],
    patterns: [
      /(?:កញ្ចប់ឥវ៉ាន់របស់អ្នកមិនអាចដឹកជញ្ជូនបាន|បង់ប្រាក់ថ្លៃសេវាដឹកជញ្ជូនឡើងវិញ|កែប្រែអាសយដ្ឋានដឹកជញ្ជូនរបស់អ្នក|ប្រៃសណីយ៍កម្ពុជាជូនដំណឹង)/,
    ],
    testCases: [
      {
        name: 'Khmer delivery address update lure',
        input: { text: 'កញ្ចប់ឥវ៉ាន់របស់អ្នកមិនអាចដឹកជញ្ជូនបានទេ សូមបង់ប្រាក់ថ្លៃសេវាដឹកជញ្ជូនឡើងវិញ $2' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer shipping notice',
        input: { text: 'ឥវ៉ាន់របស់អ្នកត្រូវបានផ្ញើតាមក្រុមហ៊ុនដឹកជញ្ជូនរួចហើយ' },
        expectedMatch: false,
      },
    ],
  }),
];
