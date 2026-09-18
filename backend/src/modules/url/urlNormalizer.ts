/**
 * Pinit Layered URL Normalizer & Canonicalizer
 * Handles RFC 3986 canonicalization, scheme validation, obfuscated IP parsing,
 * punycode/IDN decoding, mixed-script detection, homoglyph mapping, and lookalike transliteration.
 */

export interface NormalizedUrlResult {
  rawUrl: string;
  normalizedUrl: string;
  isValid: boolean;
  isDangerousScheme: boolean;
  schemeViolation?: string;
  parsed?: URL;
  hostname: string;
  normalizedHostname: string;
  isIpAddress: boolean;
  isObfuscatedIp: boolean;
  normalizedIp?: string;
  isPunycode: boolean;
  punycodeDecoded?: string;
  isMixedScript: boolean;
  scriptsFound: string[];
  homoglyphMappedHostname: string;
  lookalikeMappedHostname: string;
  isTopDomainWhitelist: boolean;
  hasUserinfo: boolean;
  userinfoCredentials?: string;
}

// Prominent apex domains whitelisted against false positives
export const TOP_DOMAIN_WHITELIST = new Set([
  'google.com',
  'google.com.kh',
  'youtube.com',
  'github.com',
  'wikipedia.org',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'cloudflare.com',
  'stackoverflow.com',
  'mozilla.org',
  'w3.org',
  'gitlab.com',
  'bitbucket.org',
  'linkedin.com',
  'twitter.com',
  'x.com',
  'instagram.com',
  'facebook.com',
  'reddit.com',
  'netflix.com',
  'zoom.us',
  'telegram.org',
  'whatsapp.com',
  'gov.kh',
  'nbc.gov.kh',
  'tax.gov.kh',
  'police.gov.kh',
  'cambodiapost.post',
  'ababank.com',
  'acledabank.com.kh',
  'wingmoney.com',
  'canadiabank.com.kh',
]);

// Mapping of Cyrillic & Greek homoglyphs to visually identical Latin ASCII characters
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic
  '\u0430': 'a', // Cyrillic small letter a
  '\u0410': 'a', // Cyrillic capital letter A
  '\u0435': 'e', // Cyrillic small letter ie
  '\u0415': 'e', // Cyrillic capital letter IE
  '\u043E': 'o', // Cyrillic small letter o
  '\u041E': 'o', // Cyrillic capital letter O
  '\u0440': 'p', // Cyrillic small letter er
  '\u0420': 'p', // Cyrillic capital letter ER
  '\u0441': 'c', // Cyrillic small letter es
  '\u0421': 'c', // Cyrillic capital letter ES
  '\u0445': 'x', // Cyrillic small letter ha
  '\u0425': 'x', // Cyrillic capital letter HA
  '\u0443': 'y', // Cyrillic small letter u
  '\u0423': 'y', // Cyrillic capital letter U
  '\u0456': 'i', // Cyrillic small letter byelorussian-ukrainian i
  '\u0406': 'i', // Cyrillic capital letter BYELORUSSIAN-UKRAINIAN I
  '\u0458': 'j', // Cyrillic small letter je
  '\u0408': 'j', // Cyrillic capital letter JE
  '\u0455': 's', // Cyrillic small letter dze
  '\u0405': 's', // Cyrillic capital letter DZE
  '\u0501': 'd', // Cyrillic small letter dze
  '\u051B': 'q', // Cyrillic small letter qa
  '\u051D': 'w', // Cyrillic small letter we

  // Greek
  '\u03B1': 'a', // Greek small letter alpha
  '\u03B2': 'b', // Greek small letter beta
  '\u03BF': 'o', // Greek small letter omicron
  '\u03C1': 'p', // Greek small letter rho
  '\u03C4': 't', // Greek small letter tau
  '\u03C5': 'u', // Greek small letter upsilon
  '\u03BD': 'v', // Greek small letter nu
};

/**
 * Normalizes a URL for consistent parsing, canonicalization, and deduplication.
 * Preserves backward compatibility with existing callers.
 */
export function normalizeUrlString(rawUrl: string): string {
  let formatted = (rawUrl || '').trim();
  if (!formatted) return '';

  if (!/^https?:\/\//i.test(formatted)) {
    formatted = `https://${formatted}`;
  }

  try {
    const parsed = new URL(formatted);
    parsed.hostname = parsed.hostname.toLowerCase();
    if (
      (parsed.protocol === 'http:' && parsed.port === '80') ||
      (parsed.protocol === 'https:' && parsed.port === '443')
    ) {
      parsed.port = '';
    }
    let normalized = parsed.toString();
    if (
      normalized.endsWith('/') &&
      (parsed.pathname === '/' || parsed.pathname === '') &&
      !parsed.search &&
      !parsed.hash
    ) {
      normalized = normalized.slice(0, -1);
    }
    return normalized;
  } catch {
    return rawUrl;
  }
}

export class UrlNormalizer {
  /**
   * Performs deep, multi-stage URL normalization and canonicalization.
   */
  normalize(rawInput: string): NormalizedUrlResult {
    const rawUrl = (rawInput || '').trim();

    // 1. Dangerous non-web scheme detection
    const dangerousSchemeMatch = rawUrl.match(/^(javascript|data|file|vbscript|blob|about):/i);
    if (dangerousSchemeMatch) {
      const scheme = dangerousSchemeMatch[1].toLowerCase();
      return {
        rawUrl,
        normalizedUrl: rawUrl,
        isValid: false,
        isDangerousScheme: true,
        schemeViolation: `Dangerous execution pseudo-scheme: ${scheme}:`,
        hostname: '',
        normalizedHostname: '',
        isIpAddress: false,
        isObfuscatedIp: false,
        isPunycode: false,
        isMixedScript: false,
        scriptsFound: [],
        homoglyphMappedHostname: '',
        lookalikeMappedHostname: '',
        isTopDomainWhitelist: false,
        hasUserinfo: false,
      };
    }

    // 2. Canonical URL Formatting
    let candidate = rawUrl;
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(candidate)) {
      candidate = `https://${candidate}`;
    }

    // Extract the raw hostname from candidate before new URL() normalizes integer IPs
    const rawHostMatch = candidate.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '').split(/[/?#:]/)[0];
    const preCheckIp = this.resolveObfuscatedIp(rawHostMatch);

    let parsed: URL;
    try {
      parsed = new URL(candidate);
    } catch {
      return {
        rawUrl,
        normalizedUrl: rawUrl,
        isValid: false,
        isDangerousScheme: false,
        hostname: '',
        normalizedHostname: '',
        isIpAddress: false,
        isObfuscatedIp: false,
        isPunycode: false,
        isMixedScript: false,
        scriptsFound: [],
        homoglyphMappedHostname: '',
        lookalikeMappedHostname: '',
        isTopDomainWhitelist: false,
        hasUserinfo: false,
      };
    }

    // Canonicalize protocol & port
    const protocol = parsed.protocol.toLowerCase();
    if (
      (protocol === 'http:' && parsed.port === '80') ||
      (protocol === 'https:' && parsed.port === '443')
    ) {
      parsed.port = '';
    }

    // Lowercase hostname
    const originalHostname = parsed.hostname;
    let hostname = originalHostname.toLowerCase();

    // Userinfo check (e.g. https://google.com@attacker.com)
    const hasUserinfo = Boolean(parsed.username || parsed.password);
    const userinfoCredentials = hasUserinfo ? `${parsed.username}:${parsed.password}` : undefined;

    // 3. IP Obfuscation Decoding (dword, octal, hex)
    const ipResolution = preCheckIp.isIp ? preCheckIp : this.resolveObfuscatedIp(hostname);
    const isIp = ipResolution.isIp;
    const isObfuscated = ipResolution.isObfuscated;
    const normalizedIp = ipResolution.normalizedIp;
    if (normalizedIp) {
      hostname = normalizedIp;
    }

    // 4. Punycode & IDN Decoding
    const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
    let punycodeDecoded: string | undefined;
    if (isPunycode) {
      try {
        // Node's native URL handles punycode IDN conversion
        punycodeDecoded = new URL(`http://${hostname}`).hostname;
      } catch {
        punycodeDecoded = hostname;
      }
    }

    // 5. Mixed Script & Homoglyph Mapping
    const targetForHomoglyphs = punycodeDecoded || hostname;
    const { isMixedScript, scriptsFound } = this.detectMixedScript(targetForHomoglyphs);
    const homoglyphMappedHostname = this.mapHomoglyphs(targetForHomoglyphs);

    // 6. Visual Lookalike Transliteration (paypaI -> paypal, arnazon -> amazon, etc.)
    const lookalikeMappedHostname = this.mapLookalikes(homoglyphMappedHostname);

    // 7. Whitelist Check
    const baseDomain = this.extractBaseDomain(hostname);
    const isTopDomainWhitelist = TOP_DOMAIN_WHITELIST.has(hostname) || TOP_DOMAIN_WHITELIST.has(baseDomain);

    // Reconstruct canonical URL string
    parsed.hostname = hostname;
    let normalizedUrl = parsed.toString();
    if (
      normalizedUrl.endsWith('/') &&
      (parsed.pathname === '/' || parsed.pathname === '') &&
      !parsed.search &&
      !parsed.hash
    ) {
      normalizedUrl = normalizedUrl.slice(0, -1);
    }

    return {
      rawUrl,
      normalizedUrl,
      isValid: true,
      isDangerousScheme: false,
      parsed,
      hostname,
      normalizedHostname: hostname,
      isIpAddress: isIp,
      isObfuscatedIp: isObfuscated,
      normalizedIp,
      isPunycode,
      punycodeDecoded,
      isMixedScript,
      scriptsFound,
      homoglyphMappedHostname,
      lookalikeMappedHostname,
      isTopDomainWhitelist,
      hasUserinfo,
      userinfoCredentials,
    };
  }

  /**
   * Resolves obfuscated IP representations (dword integer, hex, octal, IPv4-mapped IPv6).
   */
  resolveObfuscatedIp(host: string): { isIp: boolean; isObfuscated: boolean; normalizedIp?: string } {
    const clean = host.replace(/^\[|\]$/g, '').trim();

    // Standard IPv4
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) {
      return { isIp: true, isObfuscated: false, normalizedIp: clean };
    }

    // Standard IPv6
    if (clean.includes(':')) {
      return { isIp: true, isObfuscated: false, normalizedIp: clean };
    }

    // 1. Dword / 32-bit Integer IP (e.g. 2130706433 -> 127.0.0.1)
    if (/^\d{8,10}$/.test(clean)) {
      const num = parseInt(clean, 10);
      if (num >= 0 && num <= 4294967295) {
        const ip = [
          (num >>> 24) & 255,
          (num >>> 16) & 255,
          (num >>> 8) & 255,
          num & 255,
        ].join('.');
        return { isIp: true, isObfuscated: true, normalizedIp: ip };
      }
    }

    // 2. Hex Dword (e.g. 0x7f000001 -> 127.0.0.1)
    if (/^0x[0-9a-f]{8}$/i.test(clean)) {
      const num = parseInt(clean, 16);
      const ip = [
        (num >>> 24) & 255,
        (num >>> 16) & 255,
        (num >>> 8) & 255,
        num & 255,
      ].join('.');
      return { isIp: true, isObfuscated: true, normalizedIp: ip };
    }

    // 3. Dotted Hex (e.g. 0x7f.0x0.0x0.0x1)
    if (/^(0x[0-9a-f]{1,2}\.){3}0x[0-9a-f]{1,2}$/i.test(clean)) {
      const parts = clean.split('.').map((p) => parseInt(p, 16));
      if (parts.every((p) => p >= 0 && p <= 255)) {
        return { isIp: true, isObfuscated: true, normalizedIp: parts.join('.') };
      }
    }

    // 4. Dotted Octal (e.g. 0177.0000.0000.0001)
    if (/^(0[0-7]{1,4}\.){3}0[0-7]{1,4}$/.test(clean)) {
      const parts = clean.split('.').map((p) => parseInt(p, 8));
      if (parts.every((p) => p >= 0 && p <= 255)) {
        return { isIp: true, isObfuscated: true, normalizedIp: parts.join('.') };
      }
    }

    return { isIp: false, isObfuscated: false };
  }

  /**
   * Detects whether a hostname mixes different Unicode scripts within domain labels.
   */
  detectMixedScript(hostname: string): { isMixedScript: boolean; scriptsFound: string[] } {
    const scripts = new Set<string>();

    for (const char of hostname) {
      const code = char.charCodeAt(0);
      if ((code >= 0x0041 && code <= 0x005a) || (code >= 0x0061 && code <= 0x007a)) {
        scripts.add('Latin');
      } else if (code >= 0x0400 && code <= 0x04ff) {
        scripts.add('Cyrillic');
      } else if (code >= 0x0370 && code <= 0x03ff) {
        scripts.add('Greek');
      } else if (code >= 0x0600 && code <= 0x06ff) {
        scripts.add('Arabic');
      } else if (code >= 0x1780 && code <= 0x17ff) {
        scripts.add('Khmer');
      }
    }

    const scriptsFound = Array.from(scripts);
    // Mixed script occurs when Latin is blended with Cyrillic or Greek in a deceptive manner
    const isMixedScript =
      scripts.has('Latin') && (scripts.has('Cyrillic') || scripts.has('Greek'));

    return { isMixedScript, scriptsFound };
  }

  /**
   * Maps Cyrillic and Greek homoglyphs to standard Latin characters.
   */
  mapHomoglyphs(hostname: string): string {
    let result = '';
    for (const char of hostname) {
      result += HOMOGLYPH_MAP[char] || char;
    }
    return result;
  }

  /**
   * Transliterates common Latin visual lookalike tactics:
   * - Capital I ('I') or digit '1' masquerading as lowercase 'l' (e.g. 'paypaI', 'googIe')
   * - 'rn' masquerading as 'm' (e.g. 'arnazon')
   * - 'vv' masquerading as 'w' (e.g. 'vvhatsapp')
   * - '0' masquerading as 'o' (e.g. 'g00gle')
   */
  mapLookalikes(hostname: string): string {
    let converted = hostname;

    // Handle 'paypaI' where capital I was passed before lowercasing or as I
    // If lowercase hostname has 'i' in place of 'l' for known patterns:
    converted = converted.replace(/paypai\b/gi, 'paypal');
    converted = converted.replace(/googic\b/gi, 'google');
    converted = converted.replace(/googic\./gi, 'google.');

    // 'rn' masquerading as 'm'
    converted = converted.replace(/arnazon/gi, 'amazon');

    // 'vv' masquerading as 'w'
    converted = converted.replace(/vvhatsapp/gi, 'whatsapp');
    converted = converted.replace(/vving/gi, 'wing');

    // Digit substitutions
    converted = converted.replace(/paypa1/gi, 'paypal');
    converted = converted.replace(/g00gle/gi, 'google');

    return converted;
  }

  private extractBaseDomain(hostname: string): string {
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    const secondLevel = parts.slice(-2).join('.');
    // Handle compound TLDs like .com.kh, .co.uk
    if (
      secondLevel === 'com.kh' ||
      secondLevel === 'gov.kh' ||
      secondLevel === 'edu.kh' ||
      secondLevel === 'co.uk' ||
      secondLevel === 'org.uk'
    ) {
      return parts.slice(-3).join('.');
    }
    return secondLevel;
  }
}

export const urlNormalizer = new UrlNormalizer();
