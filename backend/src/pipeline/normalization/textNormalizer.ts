export interface NormalizedTextResult {
  cleanedText: string;
  deobfuscatedText: string;
  detectedLanguage: 'en' | 'km' | 'km-en' | 'unknown';
  extractedUrls: string[];
  extractedPhoneNumbers: string[];
}

export class TextNormalizer {
  // Homoglyphs and leetspeak map to uncover evasive scam text
  private static readonly LEET_MAP: Record<string, string> = {
    '@': 'a',
    '4': 'a',
    '8': 'b',
    '3': 'e',
    '1': 'i',
    '!': 'i',
    '0': 'o',
    '$': 's',
    '5': 's',
    '7': 't',
    '+': 't',
  };

  /**
   * Normalizes raw user text by:
   * 1. Performing Unicode NFKC normalization
   * 2. Stripping zero-width, invisible, and format control characters
   * 3. Collapsing multiple spaces and newlines
   * 4. De-obfuscating leetspeak and evasion attempts
   * 5. Extracting embedded URLs and contact info
   */
  normalize(raw: string): NormalizedTextResult {
    if (!raw) {
      return {
        cleanedText: '',
        deobfuscatedText: '',
        detectedLanguage: 'unknown',
        extractedUrls: [],
        extractedPhoneNumbers: [],
      };
    }

    // 1. Unicode NFKC Canonicalization
    let text = raw.normalize('NFKC');

    // 2. Remove zero-width characters and invisible evasion bytes
    // \u200B (Zero-width space), \u200C (ZWNJ), \u200D (ZWJ), \uFEFF (BOM), \u00AD (Soft hyphen)
    text = text.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g, '');

    // 3. Normalize multiple whitespaces
    const cleanedText = text.replace(/\s+/g, ' ').trim();

    // 4. De-obfuscate leetspeak for pattern matching
    let deobfuscatedText = cleanedText.toLowerCase();
    for (const [leet, char] of Object.entries(TextNormalizer.LEET_MAP)) {
      deobfuscatedText = deobfuscatedText.split(leet).join(char);
    }

    // Collapse single-letter punctuation/delimiter splits: e.g. "u.r.g.e.n.t" -> "urgent", "w-i-r-e" -> "wire"
    deobfuscatedText = deobfuscatedText.replace(/\b([a-z])(?:[.\-_*]([a-z]))+\b/gi, (match) => {
      return match.replace(/[.\-_*]/g, '');
    });

    // 5. Extract embedded URLs
    const extractedUrls = this.extractUrls(cleanedText);

    // 6. Extract phone numbers and handles
    const extractedPhoneNumbers = this.extractPhoneNumbers(cleanedText);

    // 7. Detect language
    const detectedLanguage = this.detectLanguage(cleanedText);

    return {
      cleanedText,
      deobfuscatedText,
      detectedLanguage,
      extractedUrls,
      extractedPhoneNumbers,
    };
  }

  private extractUrls(text: string): string[] {
    const urlRegex = /(https?:\/\/[^\s]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|tk|info|cc|vip|biz|site|buzz|online|me|live|app|io)[^\s]*)/gi;
    const matches = text.match(urlRegex) || [];
    return Array.from(new Set(matches.map((u) => u.replace(/[.,!?;:)\]]+$/, ''))));
  }

  private extractPhoneNumbers(text: string): string[] {
    const phoneRegex = /(\+?855\s?\d{2,3}\s?\d{3}\s?\d{3}|\+?1\s?\(?\d{3}\)?\s?\d{3}[-.\s]?\d{4}|\b0\d{8,9}\b)/g;
    const matches = text.match(phoneRegex) || [];
    return Array.from(new Set(matches));
  }

  private detectLanguage(text: string): 'en' | 'km' | 'km-en' | 'unknown' {
    const khmerRegex = /[\u1780-\u17FF\u19E0-\u19FF]/;
    const latinRegex = /[a-zA-Z]/;

    const hasKhmer = khmerRegex.test(text);
    const hasLatin = latinRegex.test(text);

    if (hasKhmer && hasLatin) return 'km-en';
    if (hasKhmer) return 'km';
    if (hasLatin) return 'en';
    return 'unknown';
  }

  /**
   * Redacts sensitive personally identifiable information (PII) before external
   * dispatching or logging:
   * - Credit card / debit card numbers (13-19 digits with optional spaces/hyphens)
   * - Passwords and explicit credentials
   * - One-Time Passwords (OTP) and verification codes
   * - US Social Security Numbers (SSN: XXX-XX-XXXX)
   */
  redactPii(text: string): string {
    if (!text) return '';
    let redacted = text;

    // 1. Credit Card Numbers (13 to 19 digits with separators)
    redacted = redacted.replace(/\b(?:\d[ -]*?){13,19}\b/g, '[REDACTED_CARD]');

    // 2. Explicit password labels e.g. "password: Secret123!", "pass: 12345"
    redacted = redacted.replace(/(password|passcode|secret|pin|pass)\s*[:=]\s*[^\s,;]+/gi, '$1: [REDACTED_CREDENTIAL]');

    // 3. One-Time Passwords / Verification Codes e.g. "OTP is 481920", "code: 582194"
    redacted = redacted.replace(/\b(otp|code|verification code|one-time password)\s*(?:[:=]|\bis\b)?\s*\b\d{4,8}\b/gi, '$1: [REDACTED_OTP]');

    // 4. US Social Security Numbers (SSN: XXX-XX-XXXX)
    redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]');

    return redacted;
  }
}

export const textNormalizer = new TextNormalizer();

