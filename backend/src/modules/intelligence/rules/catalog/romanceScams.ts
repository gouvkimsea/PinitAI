import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const romanceScamsRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-ROM-001',
    category: 'romance_scams',
    description: 'Romance relationship manipulation, overseas emergency, or love-induced investment',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['romance_scams', 'pig_butchering', 'love_scam'],
    patterns: [
      /\b(?:my love i need emergency money|military deployed overseas|customs seized my gold box|emergency transit clearance fee|fly home to marry you|save me my love|airport customs holding)\b/i,
      /\b(?:my uncle has an insider crypto platform|invest together for our future|luxury gift package.*customs|pay \$\d+ clearance fee|fee via bitcoin)\b/i,
    ],
    testCases: [
      {
        name: 'Overseas emergency money request',
        input: { text: 'My love I need emergency money for medical surgery overseas, please wire funds right away.' },
        expectedMatch: true,
      },
      {
        name: 'Pig butchering romantic investment pitch',
        input: { text: 'My uncle has an insider crypto platform let us invest together for our future wedding.' },
        expectedMatch: true,
      },
      {
        name: 'Normal dating chat',
        input: { text: 'Looking forward to meeting you for dinner this Saturday evening at 7 PM.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-ROM-KM-001',
    category: 'romance_scams',
    description: 'Romance and fake lover money extortion in Khmer',
    severity: 'high',
    confidenceContribution: 75,
    version: '1.0.0',
    tags: ['romance_scams', 'khmer', 'love_scam'],
    patterns: [
      /(?:អូនត្រូវការលុយព្យាបាលជំងឺជាបន្ទាន់|បងផ្ញើកាដូមកពីបរទេសតែជាប់គយ|វិនិយោគជាមួយគ្នាដើម្បីអនាគតពួកយើង|ផ្ញើលុយថ្លៃសំបុត្រយន្តហោះ)/,
    ],
    testCases: [
      {
        name: 'Khmer customs package romance scam',
        input: { text: 'បងផ្ញើកាដូមកពីបរទេសតែជាប់គយ សូមអូនជួយវេរលុយថ្លៃដោះលែងឥវ៉ាន់ផង' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer message',
        input: { text: 'អរគុណសម្រាប់កាដូថ្ងៃខួបកំណើត ស្រឡាញ់ពេញចិត្តខ្លាំងណាស់' },
        expectedMatch: false,
      },
    ],
  }),
];
