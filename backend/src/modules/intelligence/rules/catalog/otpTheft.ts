import { IScamRule } from '../types';
import { createPatternRule } from './ruleHelper';

export const otpTheftRules: IScamRule[] = [
  createPatternRule({
    id: 'RULE-OTP-001',
    category: 'otp_theft',
    description: 'Deceptive harvesting of SMS OTP or two-factor authentication codes',
    severity: 'critical',
    confidenceContribution: 80,
    version: '1.0.0',
    tags: ['otp_theft', '2fa', 'verification_code'],
    patterns: [
      /\b(?:(?:send|reply with|share|forward|provide|give|enter)(?: me| us)? (?:the |this )?(?:\d+-digit )?(?:otp|verification|auth|sms|login)?\s*code|what is the (?:otp|code) you just received)\b/i,
      /\b(?:forward the code sent to your phone|read the security digits to me|share the one-time passcode|reply with (?:this|the) otp|send (?:me )?(?:the )?\d+-digit code)\b/i,
    ],
    customFilter: (context) => {
      const text = `${context.text || ''} ${context.normalizedText || ''}`;
      // Do NOT trigger if the text is a legitimate advisory warning NOT to share codes
      return !/\b(?:do not share|never share|never call to ask|don't share|will never ask)\b/i.test(text);
    },
    testCases: [
      {
        name: 'SMS OTP harvesting demand',
        input: { text: 'To cancel the unauthorized transfer, send the 6-digit OTP code sent to your phone right now.' },
        expectedMatch: true,
      },
      {
        name: 'One-time passcode sharing request',
        input: { text: 'Our agent needs you to share the one-time passcode to confirm your phone ownership.' },
        expectedMatch: true,
      },
      {
        name: 'Reply with OTP prompt',
        input: { text: 'Google Account Security: We sent a 6-digit verification code. Please reply with this OTP code to secure your Gmail.' },
        expectedMatch: true,
      },
      {
        name: 'Legitimate SMS OTP warning message',
        input: { text: 'Your login code is 839201. Do NOT share this code with anyone, including bank representatives.' },
        expectedMatch: false,
      },
    ],
  }),

  createPatternRule({
    id: 'RULE-OTP-KM-001',
    category: 'otp_theft',
    description: 'OTP and SMS verification code harvesting in Khmer',
    severity: 'critical',
    confidenceContribution: 85,
    version: '1.0.0',
    tags: ['otp_theft', 'khmer', 'otp'],
    patterns: [
      /(?:ផ្ញើលេខកូដ OTP|ផ្ញើលេខកូដ [០-៩0-9]+ ខ្ទង់|លេខកូដផ្ទៀងផ្ទាត់ដែលផ្ញើទៅទូរស័ព្ទ|ប្រាប់លេខកូដសម្ងាត់ OTP|ផ្ញើលេខកូដ \d+ ខ្ទង់|ផ្ញើលេខកូដសម្ងាត់|កូដសម្ងាត់ \d+ ខ្ទង់)/,
    ],
    customFilter: (context) => {
      const text = `${context.text || ''} ${context.normalizedText || ''}`;
      return !/(?:កុំប្រាប់|កុំចែករំលែក|កុំផ្ញើ)/.test(text);
    },
    testCases: [
      {
        name: 'Khmer OTP theft demand',
        input: { text: 'សូមផ្ញើលេខកូដ OTP ៦ ខ្ទង់ដែលបានផ្ញើទៅទូរស័ព្ទរបស់អ្នកមកកាន់យើងឥឡូវនេះ' },
        expectedMatch: true,
      },
      {
        name: 'Benign Khmer OTP notice',
        input: { text: 'លេខកូដរបស់អ្នកគឺ 123456។ សូមកុំប្រាប់លេខកូដនេះទៅអ្នកដទៃ។' },
        expectedMatch: false,
      },
    ],
  }),
];
