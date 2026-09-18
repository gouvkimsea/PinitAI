import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const impersonationRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-IMPER-001',
    category: 'impersonation',
    description: 'Impersonation of banks, law enforcement, or corporate leadership',
    severity: 'high',
    confidenceContribution: 65,
    version: '1.0.0',
    tags: ['impersonation', 'bank', 'authority'],
    patterns: [
      /\b(?:this is (?:the )?(?:fraud|security) department of (?:your bank|chase|wells fargo|aba bank|acleda)|official notice from (?:the )?(?:irs|fbi|police|national bank))\b/i,
      /\b(?:(?:this is|i am) (?:the )?(?:ceo|cfo|chief financial officer|director)|(?:acting on behalf of )?executive management|wire \$[\d,]+.*immediately|treat this with (?:the )?highest confidentiality|cannot take calls.*wire)\b/i,
    ],
    testCases: [
      {
        name: 'Bank security department impersonation',
        input: { text: 'Official alert: This is the fraud department of ABA Bank notifying you of suspicious activity.' },
        expectedMatch: true,
      },
      {
        name: 'CEO wire transfer lure',
        input: { text: 'I am the CEO, please initiate a confidential wire transfer immediately before the meeting ends.' },
        expectedMatch: true,
      },
      {
        name: 'Benign executive communication',
        input: { text: 'Good morning, please see the notes from our executive staff meeting yesterday.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-IMPER-KM-001',
    category: 'impersonation',
    description: 'Impersonation of Cambodian banks or public authorities in Khmer',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['impersonation', 'khmer', 'bank', 'police'],
    patterns: [
      /(?:នាយកដ្ឋានសន្តិសុខធនាគារ|មន្ត្រីនគរបាលជាតិ|សេចក្តីជូនដំណឹងផ្លូវការពីធនាគារជាតិ|តំណាងធនាគារអេស៊ីលីដា|តំណាងធនាគារ ABA)/,
    ],
    testCases: [
      {
        name: 'Khmer police authority impersonation',
        input: { text: 'នេះគឺជាសារពីមន្ត្រីនគរបាលជាតិ សូមទាក់ទងមកវិញជាបន្ទាន់' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer message',
        input: { text: 'ធនាគារ ABA នឹងបើកដំណើរការសាខាថ្មីនៅចុងសប្តាហ៍នេះ' },
        expectedMatch: false,
      },
    ],
  }),
];
