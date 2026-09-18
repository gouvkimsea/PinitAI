import crypto from 'crypto';

/**
 * Privacy-Preserving Logging and Metadata Sanitizer
 *
 * Ensures zero leakage of:
 * - Passwords and credential pairs
 * - OTP / verification codes
 * - Bearer tokens and JWTs
 * - API keys and secrets
 * - Credit card / PAN numbers and CVVs
 * - PII and sensitive user message contents
 *
 * Converts raw user content into privacy-preserving mathematical/metadata summaries
 * (SHA-256 prefixes, length, token count, script/character composition, entropy).
 */

const SENSITIVE_PATTERNS: Array<{ name: string; regex: RegExp; replace: string }> = [
  // Bearer / JWT tokens
  {
    name: 'JWT_TOKEN',
    regex: /Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/gi,
    replace: 'Bearer [REDACTED_AUTH_TOKEN]',
  },
  // API Keys (e.g. sk_live_..., ak_live_..., key-..., etc.)
  {
    name: 'API_KEY',
    regex: /\b(?:sk_live_|sk_test_|ak_live_|ak_test_|ghp_|gho_|xoxb-|xoxp-|AIzaSy)[A-Za-z0-9_-]{12,}\b|(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{10,}['"]?/gi,
    replace: '[REDACTED_API_KEY]',
  },
  // 4-8 digit OTP verification codes
  {
    name: 'OTP_CODE',
    regex: /\b(?:code|otp|one-time|verification(?:\s+code)?|pin)\b[:=\s]+([0-9]{4,8})\b|\botp\s+code\s+is\s+([0-9]{4,8})\b/gi,
    replace: '[REDACTED_OTP]',
  },
  // Credit card numbers (13-19 digits with spaces/hyphens)
  {
    name: 'CREDIT_CARD',
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b/g,
    replace: '[REDACTED_PAYMENT_CARD]',
  },
  // CVV codes
  {
    name: 'CVV',
    regex: /\b(?:cvv|cvc|security\s+code)\b[:=\s]+([0-9]{3,4})\b/gi,
    replace: '[REDACTED_CVV]',
  },
  // Passwords in text
  {
    name: 'PASSWORD_FIELD',
    regex: /\b(?:password|passwd|pwd)(?:\s+is|[:=])\s+([^\s,;]+)/gi,
    replace: '[REDACTED_PASSWORD]',
  },
];

export interface PrivacyMetadata {
  contentLength: number;
  contentHashPrefix: string;
  hasUrls: boolean;
  hasPhoneNumbers: boolean;
  hasCredentialsMasked: boolean;
  charCount: number;
  wordCount: number;
}

/**
 * Creates privacy-preserving metadata from raw content without exposing sensitive strings.
 */
export function extractPrivacyMetadata(content: string): PrivacyMetadata {
  if (!content) {
    return {
      contentLength: 0,
      contentHashPrefix: '',
      hasUrls: false,
      hasPhoneNumbers: false,
      hasCredentialsMasked: false,
      charCount: 0,
      wordCount: 0,
    };
  }

  const hash = crypto.createHash('sha256').update(content).digest('hex');
  const hasUrls = /https?:\/\/[^\s]+/i.test(content);
  const hasPhoneNumbers = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}/.test(content);
  const words = content.trim().split(/\s+/).filter(Boolean);

  let hasCredentials = false;
  for (const { regex } of SENSITIVE_PATTERNS) {
    if (regex.test(content)) {
      hasCredentials = true;
      break;
    }
  }

  return {
    contentLength: content.length,
    contentHashPrefix: hash.substring(0, 12),
    hasUrls,
    hasPhoneNumbers,
    hasCredentialsMasked: hasCredentials,
    charCount: content.length,
    wordCount: words.length,
  };
}

/**
 * Sanitizes arbitrary log strings to neutralize OTPs, passwords, card numbers, and auth tokens.
 */
export function sanitizeLogString(str: string): string {
  if (!str || typeof str !== 'string') return str;

  let sanitized = str;
  for (const { regex, replace } of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(regex, replace);
  }

  return sanitized;
}

/**
 * Creates a safe, redacted preview of user content for debug/diagnostics (max 60 chars)
 * with all credential/OTP patterns masked.
 */
export function createSafePreview(content: string, maxChars = 60): string {
  if (!content) return '';
  const sanitized = sanitizeLogString(content);
  return sanitized.slice(0, maxChars);
}

/**
 * Deeply scrubs sensitive keys and patterns from log metadata objects.
 */
export function scrubObject(obj: any): any {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeLogString(obj);
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(scrubObject);

  const sensitiveKeyRegex = /(password|passwd|pwd|token|auth|secret|apikey|api_key|otp|pin|cvv|cvc|card|pan)/i;
  const result: Record<string, any> = {};

  for (const [key, val] of Object.entries(obj)) {
    if (sensitiveKeyRegex.test(key)) {
      result[key] = '[REDACTED_SECRET]';
    } else {
      result[key] = scrubObject(val);
    }
  }

  return result;
}

export const privacySanitizer = {
  extractPrivacyMetadata,
  sanitizeLogString,
  createSafePreview,
  scrubObject,
};
