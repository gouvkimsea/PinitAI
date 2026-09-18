import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const giveawayScamsRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-GIVE-001',
    category: 'giveaway_scams',
    description: 'Fake lottery winning notification or free high-value prize claim lure',
    severity: 'high',
    confidenceContribution: 65,
    version: '1.0.0',
    tags: ['giveaway_scams', 'lottery', 'free_iphone'],
    patterns: [
      /\b(?:congratulations! you won (?:a free iphone|\$1,000,000|the international lottery)|you have been selected as the lucky winner)\b/i,
      /\b(?:spin the wheel to claim prize|claim your free gift card within 10 minutes|pay processing fee to receive your reward)\b/i,
    ],
    testCases: [
      {
        name: 'Free iPhone lucky winner lure',
        input: { text: 'Congratulations! You won a free iPhone 15 Pro. Claim your free gift card within 10 minutes!' },
        expectedMatch: true,
      },
      {
        name: 'International lottery prize claim fee',
        input: { text: 'You have been selected as the lucky winner of $1,000,000. Pay processing fee to receive your reward.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate store loyalty rewards',
        input: { text: 'You earned 50 loyalty points on your purchase today. View your balance in the app.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-GIVE-KM-001',
    category: 'giveaway_scams',
    description: 'Lottery prize and lucky draw fraud in Khmer',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['giveaway_scams', 'khmer', 'lottery'],
    patterns: [
      /(?:អបអរសាទរ! អ្នកបានឈ្នះរង្វាន់ធំ|ឈ្នះទូរស័ព្ទ iPhone ដោយឥតគិតថ្លៃ|អ្នកជាអតិថិជនសំណាងឈ្នះឡាន|បង់ថ្លៃសេវាកាត់រង្វាន់)/,
    ],
    testCases: [
      {
        name: 'Khmer big prize winner scam',
        input: { text: 'អបអរសាទរ! អ្នកបានឈ្នះរង្វាន់ធំទូរស័ព្ទ iPhone ដោយឥតគិតថ្លៃ សូមទាក់ទងមកទទួល' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer store raffle notice',
        input: { text: 'អតិថិជនទិញទំនិញលើសពី ២០ ដុល្លារ នឹងទទួលបានសំបុត្រចាប់ឆ្នោតផ្សងសំណាង' },
        expectedMatch: false,
      },
    ],
  }),
];
