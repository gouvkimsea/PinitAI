import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const fakeShoppingRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-SHOP-001',
    category: 'fake_shopping',
    description: 'Counterfeit storefront or impossible liquidation sale lure',
    severity: 'high',
    confidenceContribution: 60,
    version: '1.0.0',
    tags: ['fake_shopping', 'e-commerce', 'clearance'],
    patterns: [
      /\b(?:warehouse closing blowout sale|all (?:macbooks|iphones|designer bags) only \$[1-9]\d|90% off clearance liquidation sale today only)\b/i,
      /\b(?:official factory outlet (?:95%|90%) discount|unclaimed package mystery boxes for \$[\d.]+)\b/i,
    ],
    testCases: [
      {
        name: 'Impossible discount MacBook blowout',
        input: { text: 'Warehouse closing blowout sale: All MacBooks only $49 today only! Free international delivery.' },
        expectedMatch: true,
      },
      {
        name: 'Mystery box liquidation lure',
        input: { text: 'Grab unclaimed package mystery boxes for $19.99 with guaranteed high-end electronics inside.' },
        expectedMatch: true,
      },
      {
        name: 'Normal seasonal sale',
        input: { text: 'Black Friday promotion: Enjoy 15% off selected apparel in-store and online.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-SHOP-KM-001',
    category: 'fake_shopping',
    description: 'Impossible discount and fake e-commerce sale lures in Khmer',
    severity: 'high',
    confidenceContribution: 65,
    version: '1.0.0',
    tags: ['fake_shopping', 'khmer', 'clearance'],
    patterns: [
      /(?:លក់បញ្ចុះតម្លៃ ៩០%|ទូរស័ព្ទ iPhone តម្លៃត្រឹមតែ \$[1-9]\d|រំលាយឃ្លាំងលក់ឡៃឡុង|ប្រអប់អាថ៌កំបាំងទំនិញ)/,
    ],
    testCases: [
      {
        name: 'Khmer fake iPhone shopping sale',
        input: { text: 'រំលាយឃ្លាំងលក់ឡៃឡុង ទូរស័ព្ទ iPhone តម្លៃត្រឹមតែ $20 តែប៉ុណ្ណោះ' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer store announcement',
        input: { text: 'ហាងយើងខ្ញុំមានលក់សម្លៀកបំពាក់គុណភាពល្អ និងតម្លៃសមរម្យ' },
        expectedMatch: false,
      },
    ],
  }),
];
