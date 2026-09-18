/**
 * Pinit Message Normalization & De-obfuscation Engine
 * Handles Unicode NFKC, homoglyphs, invisible characters, leetspeak,
 * repeated characters, defanged URLs, and internet slang.
 */

export interface NormalizedMessagePayload {
  raw: string;
  cleaned: string;
  deobfuscated: string;
  defanged: string;
  detectedLanguage: 'en' | 'km' | 'km-en' | 'unknown';
  hasObfuscation: boolean;
  obfuscationTypes: string[];
}

export class MessageNormalizer {
  // Cyrillic and Greek homoglyphs to Latin equivalents
  private static readonly HOMOGLYPH_MAP: Record<string, string> = {
    // Cyrillic lower
    '\u0430': 'a', // Cyrillic small a
    '\u0435': 'e', // Cyrillic small ie
    '\u043E': 'o', // Cyrillic small o
    '\u0440': 'p', // Cyrillic small er
    '\u0441': 'c', // Cyrillic small es
    '\u0443': 'y', // Cyrillic small u
    '\u0445': 'x', // Cyrillic small ha
    '\u0456': 'i', // Cyrillic small i
    '\u0458': 'j', // Cyrillic small je
    // Cyrillic upper
    '\u0410': 'A',
    '\u0412': 'B',
    '\u0415': 'E',
    '\u041A': 'K',
    '\u041C': 'M',
    '\u041D': 'H',
    '\u041E': 'O',
    '\u0420': 'P',
    '\u0421': 'C',
    '\u0422': 'T',
    '\u0425': 'X',
    // Greek
    '\u03B1': 'a', // alpha
    '\u03BF': 'o', // omicron
    '\u03BD': 'v', // nu
    '\u03C1': 'p', // rho
    '\u0391': 'A', // Alpha
    '\u0392': 'B', // Beta
    '\u0395': 'E', // Epsilon
    '\u039F': 'O', // Omicron
    '\u03A1': 'P', // Rho
    '\u03A4': 'T', // Tau
  };

  // Leetspeak substitutions
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
    '|': 'l',
  };

  // Common high-frequency scam keyword misspellings
  private static readonly MISSPELLING_MAP: Record<string, string> = {
    'verifcation': 'verification',
    'verificatn': 'verification',
    'paypai': 'paypal',
    'securty': 'security',
    'securtiy': 'security',
    'bannk': 'bank',
    'acount': 'account',
    'accnt': 'account',
    'passwrod': 'password',
    'passwrd': 'password',
    'suspende': 'suspended',
    'suspendd': 'suspended',
    'urgentley': 'urgently',
    'urgentt': 'urgent',
    'whatapp': 'whatsapp',
    'watsapp': 'whatsapp',
    'telegrame': 'telegram',
    'bitcion': 'bitcoin',
    'crpto': 'crypto',
    'lotery': 'lottery',
  };

  /**
   * Performs end-to-end multi-layer normalization on user message
   */
  normalize(rawText: string): NormalizedMessagePayload {
    if (!rawText || !rawText.trim()) {
      return {
        raw: '',
        cleaned: '',
        deobfuscated: '',
        defanged: '',
        detectedLanguage: 'unknown',
        hasObfuscation: false,
        obfuscationTypes: [],
      };
    }

    const obfuscationTypes: string[] = [];
    const raw = rawText;

    // 1. Unicode NFKC Normalization
    let text = raw.normalize('NFKC');

    // 2. Remove invisible formatting and zero-width characters
    const hasZeroWidth = /[\u200B-\u200D\uFEFF\u00AD\u2060-\u206F\u180E]/.test(text);
    if (hasZeroWidth) {
      obfuscationTypes.push('zero_width_characters');
      text = text.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060-\u206F\u180E]/g, '');
    }

    // 3. Convert Full-width ASCII (U+FF01 to U+FF5E) to standard ASCII
    text = text.replace(/[\uFF01-\uFF5E]/g, (ch) =>
      String.fromCharCode(ch.charCodeAt(0) - 0xFEE0)
    );

    // 4. Defang obfuscated URLs (e.g. hxxps[://]example[.]com -> https://example.com)
    const defanged = this.defangUrls(text);
    if (defanged !== text) {
      obfuscationTypes.push('url_defanging');
      text = defanged;
    }

    // 5. Replace Cyrillic & Greek homoglyphs
    let hasHomoglyphs = false;
    let homoglyphReplaced = '';
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (MessageNormalizer.HOMOGLYPH_MAP[char]) {
        hasHomoglyphs = true;
        homoglyphReplaced += MessageNormalizer.HOMOGLYPH_MAP[char];
      } else {
        homoglyphReplaced += char;
      }
    }
    if (hasHomoglyphs) {
      obfuscationTypes.push('homoglyph_confusables');
      text = homoglyphReplaced;
    }

    // 6. Normalize whitespaces (preserve clean text)
    const cleaned = text.replace(/\s+/g, ' ').trim();

    // 7. Deobfuscate for semantic & pattern matching
    let deobf = cleaned.toLowerCase();

    // 7a. Collapse deliberate single-character delimiter splits (e.g. "u.r.g.e.n.t" -> "urgent", "p-a-s-s" -> "pass")
    const delimiterCollapsed = deobf.replace(/\b([a-z0-9])(?:[.\-_*~^]([a-z0-9]))+\b/gi, (match) => {
      // Don't collapse legitimate domain names or IPs
      if (/\.(com|net|org|edu|gov|io|xyz|top|info|me|co|kh)\b/i.test(match)) return match;
      if (/^\d+\.\d+\.\d+\.\d+$/.test(match)) return match;
      return match.replace(/[.\-_*~^]/g, '');
    });
    if (delimiterCollapsed !== deobf) {
      obfuscationTypes.push('delimited_words');
      deobf = delimiterCollapsed;
    }

    // 7b. Leetspeak substitution (apply carefully to isolated or word tokens)
    let leetReplaced = deobf;
    for (const [leet, char] of Object.entries(MessageNormalizer.LEET_MAP)) {
      leetReplaced = leetReplaced.split(leet).join(char);
    }
    if (leetReplaced !== deobf) {
      obfuscationTypes.push('leetspeak');
      deobf = leetReplaced;
    }

    // 7c. Repeated characters reduction (e.g. "urgentttt" -> "urgent", "freeeee" -> "free")
    // Replace 3 or more of any character with max 2, unless 2 is already standard
    const repeatedNormalized = deobf.replace(/([a-z])\1{2,}/g, '$1');
    if (repeatedNormalized !== deobf) {
      obfuscationTypes.push('repeated_characters');
      deobf = repeatedNormalized;
    }

    // 7d. Correct scam keyword misspellings
    const words = deobf.split(/\s+/);
    let corrected = false;
    const normalizedWords = words.map((w) => {
      const cleanW = w.replace(/[^a-z0-9]/g, '');
      if (MessageNormalizer.MISSPELLING_MAP[cleanW]) {
        corrected = true;
        return MessageNormalizer.MISSPELLING_MAP[cleanW];
      }
      return w;
    });
    if (corrected) {
      obfuscationTypes.push('keyword_misspelling');
      deobf = normalizedWords.join(' ');
    }

    // 8. Detect Language
    const detectedLanguage = this.detectLanguage(cleaned);

    return {
      raw,
      cleaned,
      deobfuscated: deobf,
      defanged,
      detectedLanguage,
      hasObfuscation: obfuscationTypes.length > 0,
      obfuscationTypes: Array.from(new Set(obfuscationTypes)),
    };
  }

  /**
   * Defangs obfuscated URLs in text
   * Handles: hxxp://, hxxps://, [.] instead of ., [://] instead of ://, "example . com"
   */
  private defangUrls(text: string): string {
    let res = text;
    // 1. Replace [://] or (://) first
    res = res.replace(/\[:\/\/\]|\(:\/\/\)/g, '://');
    // 2. Replace hxxp:// and hxxps://
    res = res.replace(/hxxps?:\/\//gi, (match) => match.toLowerCase().replace('hxxp', 'http'));
    // 3. Replace [.] or (.) or (dot) or [dot]
    res = res.replace(/\[\.\]|\(\.\)|\[dot\]|\(dot\)/gi, '.');
    // 4. Replace domain spacing e.g. "google . com", "t . me"
    res = res.replace(/\b([a-zA-Z0-9-]+)\s+\.\s+(com|org|net|xyz|top|tk|info|cc|vip|biz|site|me|live|app|io|kh)\b/gi, '$1.$2');
    return res;
  }

  /**
   * Identifies script and language category
   */
  private detectLanguage(text: string): 'en' | 'km' | 'km-en' | 'unknown' {
    const hasKhmer = /[\u1780-\u17FF\u19E0-\u19FF]/.test(text);
    const hasEnglish = /[a-zA-Z]/.test(text);

    if (hasKhmer && hasEnglish) return 'km-en';
    if (hasKhmer) return 'km';
    if (hasEnglish) return 'en';
    return 'unknown';
  }
}

export const messageNormalizer = new MessageNormalizer();
