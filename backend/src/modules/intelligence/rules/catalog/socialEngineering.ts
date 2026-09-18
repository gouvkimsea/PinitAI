import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const socialEngineeringRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-SOC-001',
    category: 'social_engineering',
    description: 'Artificial extreme urgency, intimidation, or threats of legal arrest/account destruction',
    severity: 'medium',
    confidenceContribution: 40,
    version: '1.0.0',
    tags: ['social_engineering', 'urgency', 'intimidation'],
    patterns: [
      /\b(?:act within (?:5|10|15|30) minutes or (?:face arrest|account will be permanently deleted)|failure to comply will result in immediate legal prosecution)\b/i,
      /\b(?:do not hang up this call or tell anyone|keep this strictly confidential from family|a warrant has been issued for your arrest)\b/i,
    ],
    testCases: [
      {
        name: 'Urgent threat of arrest',
        input: { text: 'A warrant has been issued for your arrest. Act within 15 minutes or face arrest by local authorities.' },
        expectedMatch: true,
      },
      {
        name: 'Secrecy and isolation tactic',
        input: { text: 'This matter is classified. Do not hang up this call or tell anyone in your household.' },
        expectedMatch: true,
      },
      {
        name: 'Standard business deadline',
        input: { text: 'Reminder: please submit your timesheet before Friday 5 PM.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-SOC-KM-001',
    category: 'social_engineering',
    description: 'Threats and coercive urgency manipulation in Khmer',
    severity: 'medium',
    confidenceContribution: 45,
    version: '1.0.0',
    tags: ['social_engineering', 'khmer', 'intimidation'],
    patterns: [
      /(?:គណនីរបស់អ្នកនឹងត្រូវលុបជាអចិន្ត្រៃយ៍ក្នុងរយៈពេល|ដីកាចាប់ខ្លួនត្រូវបានចេញ|កុំប្រាប់អ្នកណាឱ្យសោះ|ចាត់វិធានការជាបន្ទាន់ក្នុងរយៈពេល)/,
    ],
    testCases: [
      {
        name: 'Khmer intimidation threat',
        input: { text: 'ដីកាចាប់ខ្លួនត្រូវបានចេញសម្រាប់អ្នក សូមកុំប្រាប់អ្នកណាឱ្យសោះ' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer reminder',
        input: { text: 'កុំភ្លេចចូលរួមការប្រជុំនៅម៉ោង ៣ រសៀលនេះ' },
        expectedMatch: false,
      },
    ],
  }),
];
