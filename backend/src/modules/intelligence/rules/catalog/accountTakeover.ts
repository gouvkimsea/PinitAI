import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const accountTakeoverRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-ATO-001',
    category: 'account_takeover',
    description: 'SIM swap alert, unauthorized password reset hijacked link, or recovery channel redirection',
    severity: 'critical',
    confidenceContribution: 75,
    version: '1.0.0',
    tags: ['account_takeover', 'sim_swap', 'password_reset'],
    patterns: [
      /\b(?:your sim card has been reassigned to a new device|sim swap request initiated|if this was not you click here to stop transfer|requested a sim transfer|stop identity transfer|cancel \d+)\b/i,
      /\b(?:your account primary email was changed to|password reset link requested from unknown ip|confirm authorization to transfer account ownership)\b/i,
    ],
    testCases: [
      {
        name: 'SIM swap alert phishing lure',
        input: { text: 'Alert: Your SIM card has been reassigned to a new device. If this was not you click here to stop transfer immediately.' },
        expectedMatch: true,
      },
      {
        name: 'Account ownership transfer lure',
        input: { text: 'Security notice: Confirm authorization to transfer account ownership to external administrator.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate password change receipt',
        input: { text: 'Your password was changed successfully on September 18 at 10:30 AM from your saved browser.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-ATO-KM-001',
    category: 'account_takeover',
    description: 'Account takeover and SIM swap alerts in Khmer',
    severity: 'critical',
    confidenceContribution: 80,
    version: '1.0.0',
    tags: ['account_takeover', 'khmer', 'sim_swap'],
    patterns: [
      /(?:ស៊ីមកាតរបស់អ្នកត្រូវបានប្តូរទៅឧបករណ៍ថ្មី|គណនីរបស់អ្នកត្រូវបានស្នើសុំប្តូរពាក្យសម្ងាត់|ការផ្ទេរសិទ្ធិកាន់កាប់គណនី|សំណើផ្ទេរលេខទូរស័ព្ទ|ផ្ទេរលេខទូរស័ព្ទរបស់អ្នក)/,
    ],
    testCases: [
      {
        name: 'Khmer SIM swap takeover lure',
        input: { text: 'ស៊ីមកាតរបស់អ្នកត្រូវបានប្តូរទៅឧបករណ៍ថ្មី ប្រសិនបើមិនមែនជាអ្នកទេ សូមចុចទីនេះ' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer message',
        input: { text: 'អ្នកបានប្តូរលេខទូរស័ព្ទក្នុងប្រព័ន្ធដោយជោគជ័យ' },
        expectedMatch: false,
      },
    ],
  }),
];
