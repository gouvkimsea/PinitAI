import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const phishingRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-PHISH-001',
    category: 'phishing',
    description: 'Deceptive verification or re-authentication lure to steal portal credentials',
    severity: 'high',
    confidenceContribution: 65,
    version: '1.0.0',
    tags: ['phishing', 'credentials', 'portal'],
    patterns: [
      /\b(?:urgent security update|click here to verify your (?:account|identity)|re-authenticate to prevent suspension|confirm your login details|verify your account immediately|verify ownership(?: here)?|before account lock)\b/i,
      /\b(?:your mailbox is full|storage quota exceeded|validate your email credentials|fb-support|security-portal|verify-security)\b/i,
    ],
    testCases: [
      {
        name: 'Urgent security account verification lure',
        input: { text: 'Alert: Click here to verify your account immediately or access will be revoked.' },
        expectedMatch: true,
      },
      {
        name: 'Mailbox quota lure',
        input: { text: 'Warning: storage quota exceeded! Please validate your email credentials now.' },
        expectedMatch: true,
      },
      {
        name: 'Normal benign communication',
        input: { text: 'Hello team, the weekly security metrics report is attached for review.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-PHISH-KM-001',
    category: 'phishing',
    description: 'Phishing credential harvesting portal lure in Khmer',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['phishing', 'khmer', 'portal'],
    patterns: [
      /(?:ចុចទីនេះដើម្បីបញ្ជាក់|ផ្ទៀងផ្ទាត់គណនីរបស់អ្នក|ការចូលប្រើប្រាស់ដោយគ្មានការអនុញ្ញាត|បញ្ជាក់គណនីរបស់អ្នកជាបន្ទាន់)/,
    ],
    testCases: [
      {
        name: 'Khmer account verification portal lure',
        input: { text: 'សូមចុចទីនេះដើម្បីបញ្ជាក់គណនីរបស់អ្នកជាបន្ទាន់ដើម្បីកុំឱ្យបិទ' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer text',
        input: { text: 'សួស្តីបង សូមផ្ញើឯកសារកិច្ចសន្យាមកខ្ញុំផង' },
        expectedMatch: false,
      },
    ],
  }),
];
