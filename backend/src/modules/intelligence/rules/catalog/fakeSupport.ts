import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const fakeSupportRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-SUPP-001',
    category: 'fake_support',
    description: 'Fake tech support alert demanding immediate phone call or remote access software install',
    severity: 'critical',
    confidenceContribution: 75,
    version: '1.0.0',
    tags: ['fake_support', 'tech_support', 'remote_access'],
    patterns: [
      /\b(?:critical system alert: (?:trojan|malware|virus) detected|call microsoft support immediately at 1-\d{3}-\d{3}-\d{4}|your computer is locked)\b/i,
      /\b(?:install (?:anydesk|teamviewer|ultraviewer) to allow technician access|remote technical support fee required to fix virus)\b/i,
    ],
    testCases: [
      {
        name: 'Critical virus popup phone lure',
        input: { text: 'Critical system alert: Trojan detected! Do not restart. Call Microsoft support immediately at 1-800-555-0199.' },
        expectedMatch: true,
      },
      {
        name: 'Remote access software installation demand',
        input: { text: 'Please install AnyDesk to allow technician access so we can remove the trojan virus from your PC.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate helpdesk ticket',
        input: { text: 'Your IT support ticket #4829 has been resolved by our desktop support team.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-SUPP-KM-001',
    category: 'fake_support',
    description: 'Tech support and fake security helpdesk scams in Khmer',
    severity: 'critical',
    confidenceContribution: 80,
    version: '1.0.0',
    tags: ['fake_support', 'khmer', 'tech_support'],
    patterns: [
      /(?:កុំព្យូទ័ររបស់អ្នកឆ្លងមេរោគ|ទូរស័ព្ទទៅផ្នែកបច្ចេកទេសជាបន្ទាន់|ដំឡើងកម្មវិធីបញ្ជាពីចម្ងាយ AnyDesk|កុំបិទកុំព្យូទ័រ)/,
    ],
    testCases: [
      {
        name: 'Khmer tech support alert lure',
        input: { text: 'កុំព្យូទ័ររបស់អ្នកឆ្លងមេរោគកាចសាហាវ សូមទូរស័ព្ទទៅផ្នែកបច្ចេកទេសជាបន្ទាន់' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer IT message',
        input: { text: 'ប្រព័ន្ធនឹងធ្វើការថែទាំប្រចាំខែនៅយប់ថ្ងៃសៅរ៍' },
        expectedMatch: false,
      },
    ],
  }),
];
