import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const fakeEmploymentRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-JOB-001',
    category: 'fake_employment',
    description: 'Task-based recruitment scam or upfront fee job offer',
    severity: 'high',
    confidenceContribution: 65,
    version: '1.0.0',
    tags: ['fake_employment', 'task_scam', 'job_offer'],
    patterns: [
      /\b(?:(?:like|rate|rating) (?:travel )?(?:youtube|tiktok) videos|earn \$[1-9]\d{1,3}(?:-\$[1-9]\d{1,3})?\s?(?:daily|per day)|complete (?:simple )?rating tasks|(?:vip task|daily deposit|deposit required for vip))\b/i,
      /\b(?:hiring immediately no interview required|remote data (?:entry|specialists).*earn|no experience required.*deposit|pay training deposit before starting)\b/i,
    ],
    testCases: [
      {
        name: 'TikTok video rating task lure',
        input: { text: 'Part-time opportunity: Like TikTok videos to earn $300 to $800 daily from your mobile phone.' },
        expectedMatch: true,
      },
      {
        name: 'VIP task recharge requirement',
        input: { text: 'Your task account is negative. Complete VIP task recharge required to withdraw your commissions.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate job posting',
        input: { text: 'We are hiring a Senior Software Engineer in Phnom Penh. Please review requirements and submit CV.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-JOB-KM-001',
    category: 'fake_employment',
    description: 'Task-based online job scams in Khmer',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['fake_employment', 'khmer', 'task_scam'],
    patterns: [
      /(?:ការងារក្រៅម៉ោង|រកចំណូលប្រចាំថ្ងៃ|ធ្វើការងារតាមទូរស័ព្ទ|មើលវីដេអូបានលុយ|បញ្ចូលលុយដើម្បីបំពេញភារកិច្ច)/,
    ],
    testCases: [
      {
        name: 'Khmer task scam recruitment',
        input: { text: 'ស្វែងរកការងារក្រៅម៉ោង មើលវីដេអូបានលុយ រកចំណូលប្រចាំថ្ងៃ $50 ទៅ $200' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer employment notice',
        input: { text: 'ក្រុមហ៊ុនត្រូវការជ្រើសរើសបុគ្គលិកគណនេយ្យ ១ នាក់' },
        expectedMatch: false,
      },
    ],
  }),
];
