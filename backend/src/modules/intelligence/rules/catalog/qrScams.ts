import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const qrScamsRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-QR-001',
    category: 'qr_scams',
    description: 'Deceptive QR code lure (quishing), parking meter sticker replacement, or scan-to-claim cash',
    severity: 'high',
    confidenceContribution: 70,
    version: '1.0.0',
    tags: ['qr_scams', 'quishing', 'qr_code'],
    patterns: [
      /\b(?:scan (?:this )?qr code to (?:claim (?:cash|prize|reward)|verify your banking login)|scan qr code to pay parking fine)\b/i,
      /\b(?:scan the attached qr code to authorize login|fake qr sticker placed over merchant payment code)\b/i,
    ],
    testCases: [
      {
        name: 'Scan QR to claim prize lure',
        input: { text: 'Congratulations! Scan this QR code to claim cash prize of $500 directly to your account.' },
        expectedMatch: true,
      },
      {
        name: 'Scan QR to verify bank login',
        input: { text: 'Security notice: Scan the attached QR code to authorize login on your desktop browser.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate restaurant menu QR code',
        input: { text: 'Welcome to the bistro. Please scan the QR code on your table to view our digital menu.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-QR-KM-001',
    category: 'qr_scams',
    description: 'Fraudulent QR code payment and quishing lures in Khmer',
    severity: 'high',
    confidenceContribution: 75,
    version: '1.0.0',
    tags: ['qr_scams', 'khmer', 'qr_code'],
    patterns: [
      /(?:ស្កេន (?:KH)?QR (?:កូដ)?ដើម្បីទទួល(?:បាន)?(?:ប្រាក់រង្វាន់|ប្រាក់ឧបត្ថម្ភ|រង្វាន់)|ស្កេន (?:KH)?QR ដើម្បីផ្ទៀងផ្ទាត់គណនីធនាគារ|បិទតែម QR ក្លែងក្លាយលើ QR ពិត)/,
    ],
    testCases: [
      {
        name: 'Khmer scan QR for reward scam',
        input: { text: 'សូមស្កេន QR កូដដើម្បីទទួលប្រាក់រង្វាន់ $100 ភ្លាមៗ' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer payment QR notice',
        input: { text: 'អតិថិជនអាចទូទាត់ប្រាក់តាមរយៈ KHQR របស់ធនាគារណាក៏បាន' },
        expectedMatch: false,
      },
    ],
  }),
];
