import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const cryptoScamsRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-CRYPTO-001',
    category: 'crypto_scams',
    description: 'Seed phrase / private key solicitation, crypto doubling, or wallet drainer approval lure',
    severity: 'critical',
    confidenceContribution: 80,
    version: '1.0.0',
    tags: ['crypto_scams', 'seed_phrase', 'doubler'],
    patterns: [
      /(?<!(?:never|do not|don't)\s+)\b(?:enter your 12-word seed phrase|share your secret recovery phrase|send your metamask private key)\b/i,
      /\b(?:send 1 (?:btc|eth|sol) get 2 back|crypto giveaway doubling promotion|connect wallet to claim 5000 usdt airdrop)\b/i,
    ],
    testCases: [
      {
        name: 'Seed phrase solicitation',
        input: { text: 'To synchronize your blockchain wallet, enter your 12-word seed phrase in the validator window.' },
        expectedMatch: true,
      },
      {
        name: 'Crypto doubler giveaway lure',
        input: { text: 'Elon Musk official promotion: Send 1 ETH get 2 back automatically within 10 minutes!' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate crypto wallet security advice',
        input: { text: 'Security rule #1: Never share your secret recovery phrase with any website or support personnel.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-CRYPTO-KM-001',
    category: 'crypto_scams',
    description: 'Cryptocurrency investment and wallet theft in Khmer',
    severity: 'critical',
    confidenceContribution: 85,
    version: '1.0.0',
    tags: ['crypto_scams', 'khmer', 'wallet_theft'],
    patterns: [
      /(?:បញ្ចូលឃ្លាសម្ងាត់កាបូបលុយ|ផ្ញើលេខកូដសម្ងាត់ recovery phrase|ផ្ទេរ 1 BTC ទទួលបាន 2 BTC ត្រឡប់មកវិញ|ទទួលកាក់ Airdrop ដោយឥតគិតថ្លៃ)/,
    ],
    testCases: [
      {
        name: 'Khmer crypto wallet recovery phrase theft',
        input: { text: 'សូមបញ្ចូលឃ្លាសម្ងាត់កាបូបលុយរបស់អ្នកដើម្បីធ្វើបច្ចុប្បន្នភាពកាបូបឌីជីថល' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer blockchain news',
        input: { text: 'តម្លៃរូបិយប័ណ្ណគ្រីបតូមានការកើនឡើងកាលពីម្សិលមិញ' },
        expectedMatch: false,
      },
    ],
  }),
];
