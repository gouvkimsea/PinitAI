import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const credentialTheftRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-CRED-001',
    category: 'credential_theft',
    description: 'Solicitation or harvesting of account passwords, PIN codes, or master credentials',
    severity: 'critical',
    confidenceContribution: 75,
    version: '1.0.0',
    tags: ['credential_theft', 'password', 'pin'],
    patterns: [
      /\b(?:send (?:me )?(?:your )?(?:current )?password|provide your (?:current )?(?:login )?(?:password|credentials|(?:atm |banking )?pin (?:code)?)|what is your account password|enter your password to proceed)\b/i,
      /\b(?:share your security questions and answers|type your username and password here|reply with your credentials)\b/i,
    ],
    testCases: [
      {
        name: 'Direct password solicitation',
        input: { text: 'Security check: Reply with your credentials including your current password and username.' },
        expectedMatch: true,
      },
      {
        name: 'ATM PIN request',
        input: { text: 'To unfreeze your card, provide your ATM PIN code to the representative immediately.' },
        expectedMatch: true,
      },
      {
        name: 'Login password appeal lure',
        input: { text: 'Meta: Provide your current login password and registered email to file appeal.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate password advice',
        input: { text: 'Tips for safety: Never share your password with anyone, our staff will never ask for it.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-CRED-KM-001',
    category: 'credential_theft',
    description: 'Direct password and PIN harvesting in Khmer',
    severity: 'critical',
    confidenceContribution: 80,
    version: '1.0.0',
    tags: ['credential_theft', 'khmer', 'password'],
    patterns: [
      /(?:ផ្ញើលេខសម្ងាត់របស់អ្នក|ប្រាប់លេខកូដសម្ងាត់|លេខកូដ PIN របស់ធនាគារ|បញ្ចូលពាក្យសម្ងាត់របស់អ្នក|បញ្ចូលលេខសម្ងាត់|លេខសម្ងាត់កាត ATM)/,
    ],
    testCases: [
      {
        name: 'Khmer password harvesting lure',
        input: { text: 'សូមផ្ញើលេខសម្ងាត់របស់អ្នកមកកាន់យើងខ្ញុំដើម្បីដោះសោគណនី' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer security tip',
        input: { text: 'កុំចែករំលែកលេខសម្ងាត់របស់អ្នកជាមួយនរណាម្នាក់ឡើយ' },
        expectedMatch: false,
      },
    ],
  }),
];
