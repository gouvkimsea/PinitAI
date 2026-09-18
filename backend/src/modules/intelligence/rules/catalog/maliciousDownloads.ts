import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const maliciousDownloadsRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-DOWN-001',
    category: 'malicious_downloads',
    description: 'Fake browser update, free cracked software installer, or rogue codec download lure',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['malicious_downloads', 'fake_update', 'cracked_software'],
    patterns: [
      /\b(?:your (?:chrome|firefox|browser) is out of date! click here to download update|mandatory browser security patch installer\.exe)\b/i,
      /\b(?:download full cracked (?:photoshop|windows|office) free keygen|missing media player codec download setup\.exe)\b/i,
    ],
    testCases: [
      {
        name: 'Fake Chrome update lure',
        input: { text: 'Warning: Your Chrome is out of date! Click here to download update to continue browsing.' },
        expectedMatch: true,
      },
      {
        name: 'Cracked software keygen lure',
        input: { text: 'Download full cracked Photoshop free keygen with serial license activator.' },
        expectedMatch: true,
      },
      {
        name: 'Official software release note',
        input: { text: 'Google Chrome version 128 is now rolling out via the standard background updater.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-DOWN-KM-001',
    category: 'malicious_downloads',
    description: 'Fake updates and malicious software downloads in Khmer',
    severity: 'high',
    confidenceContribution: 75,
    version: '1.0.0',
    tags: ['malicious_downloads', 'khmer', 'fake_update'],
    patterns: [
      /(?:កម្មវិធីរុករករបស់អ្នកហួសសម័យ|ទាញយកការអាប់ដេតកម្មវិធី browser|ទាញយកកម្មវិធី cracked ដោយឥតគិតថ្លៃ)/,
    ],
    testCases: [
      {
        name: 'Khmer fake browser update lure',
        input: { text: 'កម្មវិធីរុករករបស់អ្នកហួសសម័យ សូមទាញយកការអាប់ដេតកម្មវិធី browser ជាបន្ទាន់' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer update message',
        input: { text: 'ប្រព័ន្ធប្រតិបត្តិការទូរស័ព្ទមានការអាប់ដេតកំណែថ្មី' },
        expectedMatch: false,
      },
    ],
  }),
];
