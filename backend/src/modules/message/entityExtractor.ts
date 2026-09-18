/**
 * Pinit Message Entity Extractor
 * Extracts URLs, phone numbers, email addresses, crypto wallets,
 * payment/bank handles, messaging usernames, brands, and requested sensitive data.
 */

import {
  ExtractedEntities,
  CryptoEntity,
  BankAccountEntity,
  PaymentHandleEntity,
  SocialHandleEntity,
} from './types';

export class EntityExtractor {
  // Common URL shorteners frequently abused in smishing campaigns
  public static readonly SHORTENERS = new Set([
    'bit.ly',
    'tinyurl.com',
    't.co',
    'cutt.ly',
    'is.gd',
    'rb.gy',
    'ow.ly',
    'tiny.cc',
    's.id',
    'shorturl.at',
    'v.gd',
    't.ly',
  ]);

  // Trusted and recognized brands monitored for impersonation
  private static readonly RECOGNIZED_BRANDS: Array<{ name: string; regex: RegExp }> = [
    // Cambodian Financial Institutions & Authorities
    { name: 'ABA Bank', regex: /\b(aba(?:\s+bank)?|advanced\s+bank\s+of\s+asia|ធនាគារ\s*aba)\b/i },
    { name: 'Wing Bank', regex: /\b(wing(?:\s+bank)?|wing\s+money|ធនាគារ\s*វីង)\b/i },
    { name: 'ACLEDA Bank', regex: /\b(acleda(?:\s+bank)?|ធនាគារ\s*អេស៊ីលីដា)\b/i },
    { name: 'Canadia Bank', regex: /\b(canadia(?:\s+bank)?|ធនាគារ\s*កាណាឌីយ៉ា)\b/i },
    { name: 'Bakong / NBC', regex: /\b(bakong|national\s+bank\s+of\s+cambodia|ធនាគារជាតិនៃកម្ពុជា|បាគង)\b/i },
    { name: 'GDT (Taxation)', regex: /\b(gdt|general\s+department\s+of\s+taxation|អគ្គនាយកដ្ឋានពន្ធដារ)\b/i },
    { name: 'Cambodian Police / Court', regex: /\b(cambodian\s+police|national\s+police|នគរបាលជាតិ|កងរាជអាវុធហត្ថ|តុលាការ)\b/i },

    // Global Tech & Finance
    { name: 'Telegram', regex: /\b(telegram|tele\s+support|t\.me)\b/i },
    { name: 'WhatsApp', regex: /\b(whatsapp|whatapp|wa\.me)\b/i },
    { name: 'Meta / Facebook', regex: /\b(meta(?:\s+support)?|facebook(?:\s+security)?|fb\s+team)\b/i },
    { name: 'Apple', regex: /\b(apple(?:\s+support|\s+id|\s+security)?|icloud)\b/i },
    { name: 'Google', regex: /\b(google(?:\s+security|\s+account|\s+workspace)?)\b/i },
    { name: 'PayPal', regex: /\b(paypal|pay\s*pal)\b/i },
    { name: 'Binance', regex: /\b(binance|binance\s+support)\b/i },
    { name: 'Amazon', regex: /\b(amazon(?:\s+security|\s+prime|\s+support)?)\b/i },
    { name: 'Microsoft', regex: /\b(microsoft(?:\s+support|\s+windows|\s+365)?)\b/i },
    { name: 'Netflix', regex: /\b(netflix(?:\s+support|\s+billing)?)\b/i },
    { name: 'Pinit Security', regex: /\b(pinit(?:\s+support|\s+team|\s+security)?)\b/i },
  ];

  /**
   * Extracts all structured entities from clean and deobfuscated message text
   */
  extract(cleanedText: string, deobfuscatedText: string): ExtractedEntities {
    const urls = this.extractUrls(cleanedText);
    const phoneNumbers = this.extractPhoneNumbers(cleanedText);
    const emailAddresses = this.extractEmails(cleanedText);
    const cryptoAddresses = this.extractCryptoAddresses(cleanedText);
    const bankAccounts = this.extractBankAccounts(cleanedText);
    const paymentHandles = this.extractPaymentHandles(cleanedText, deobfuscatedText);
    const socialHandles = this.extractSocialHandles(cleanedText);
    const brands = this.extractBrands(cleanedText);
    const requestedCredentials = this.extractRequestedCredentials(deobfuscatedText);

    return {
      urls,
      phoneNumbers,
      emailAddresses,
      cryptoAddresses,
      bankAccounts,
      paymentHandles,
      socialHandles,
      brands,
      requestedCredentials,
    };
  }

  /**
   * Extracts URLs (standard, shortened, and defanged)
   */
  private extractUrls(text: string): string[] {
    const tlds = 'com|org|net|edu|gov|xyz|top|tk|info|cc|vip|biz|site|buzz|online|me|live|app|io|kh|ly|co|gd|gy|to|is|gl|link|dev|ai|cloud|click|club|space|fun|shop|pro|rest|icu|work|id|at|mobi|asia|so|cx|ms|vg|gs|ws';
    const urlRegex = new RegExp(
      `(?:https?:\\/\\/|www\\.)[^\\s<>"'{}|\\\\^\`]+|(?<![@\\/])\\b[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*\\.(?:${tlds})(?:\\/[^\\s<>"'{}|\\\\^\`]*)?`,
      'gi'
    );
    const matches = text.match(urlRegex) || [];
    const sanitized = matches.map((u) => {
      let clean = u.replace(/[.,!?;:)\]]+$/, '');
      if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
        clean = `https://${clean}`;
      }
      return clean;
    });
    return Array.from(new Set(sanitized));
  }

  /**
   * Extracts phone numbers (Cambodian +855 / 0xx, and International E.164)
   */
  private extractPhoneNumbers(text: string): string[] {
    const phoneRegex = /(?:\+?855[\s.-]?(?:[1-9]\d{1,2})[\s.-]?\d{3}[\s.-]?\d{3,4}|\b0[1-9]\d{1,2}[\s.-]?\d{3}[\s.-]?\d{3,4}\b|\+?1[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}|\b\+?[2-9]\d{1,3}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b)/g;
    const matches = text.match(phoneRegex) || [];
    // Clean spaces and formatting
    const cleaned = matches.map((p) => p.replace(/[^\d+]/g, ''));
    return Array.from(new Set(cleaned));
  }

  /**
   * Extracts email addresses
   */
  private extractEmails(text: string): string[] {
    const emailRegex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
    const matches = text.match(emailRegex) || [];
    return Array.from(new Set(matches.map((e) => e.toLowerCase())));
  }

  /**
   * Extracts cryptocurrency wallet addresses (Bitcoin, Ethereum, USDT TRC20, Solana)
   */
  private extractCryptoAddresses(text: string): CryptoEntity[] {
    const results: CryptoEntity[] = [];

    // Ethereum / ERC20 (0x + 40 hex chars)
    const ethRegex = /\b(0x[a-fA-F0-9]{40})\b/g;
    let match;
    while ((match = ethRegex.exec(text)) !== null) {
      results.push({ type: 'ETH', address: match[1] });
    }

    // TRON / TRC20 (USDT TRC20 starts with T and is 34 base58 chars)
    const tronRegex = /\b(T[a-zA-Z0-9]{33})\b/g;
    while ((match = tronRegex.exec(text)) !== null) {
      results.push({ type: 'USDT_TRC20', address: match[1] });
    }

    // Bitcoin (Legacy 1..., P2SH 3..., Bech32 bc1...)
    const btcRegex = /\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g;
    while ((match = btcRegex.exec(text)) !== null) {
      results.push({ type: 'BTC', address: match[1] });
    }

    return results;
  }

  /**
   * Extracts bank account numbers (e.g. ABA Bank 9-10 digit accounts, Wing 8-10 digit accounts)
   */
  private extractBankAccounts(text: string): BankAccountEntity[] {
    const results: BankAccountEntity[] = [];

    // Explicit ABA account pattern: "ABA: 000 123 456" or "ABA account 000123456"
    const abaRegex = /(?:aba(?:\s+account|\s+no|\s+number)?:?\s*)(\d{3}[\s.-]?\d{3}[\s.-]?\d{3,4})\b/gi;
    let match;
    while ((match = abaRegex.exec(text)) !== null) {
      results.push({
        bank: 'ABA Bank',
        accountNumber: match[1].replace(/[\s.-]/g, ''),
        raw: match[0],
      });
    }

    // Explicit Wing account pattern
    const wingRegex = /(?:wing(?:\s+account|\s+no|\s+number)?:?\s*)(\d{8,10})\b/gi;
    while ((match = wingRegex.exec(text)) !== null) {
      results.push({
        bank: 'Wing Bank',
        accountNumber: match[1],
        raw: match[0],
      });
    }

    // Generic bank account pattern: "account number: 123456789"
    const genericRegex = /(?:bank\s+account|acc(?:\s+no|\s+number)?:?\s*)(\d{8,16})\b/gi;
    while ((match = genericRegex.exec(text)) !== null) {
      results.push({
        accountNumber: match[1],
        raw: match[0],
      });
    }

    return results;
  }

  /**
   * Extracts payment handles (Bakong, KHQR, PayPal, CashApp, Zelle)
   */
  private extractPaymentHandles(cleanedText: string, deobfText: string): PaymentHandleEntity[] {
    const handles: PaymentHandleEntity[] = [];

    // CashApp handles: $username
    const cashAppRegex = /\$([a-zA-Z][a-zA-Z0-9_]{1,19})\b/g;
    let match;
    while ((match = cashAppRegex.exec(cleanedText)) !== null) {
      handles.push({ provider: 'CashApp', identifier: match[0] });
    }

    // PayPal usernames / links: paypal.me/username
    const paypalRegex = /paypal\.me\/([a-zA-Z0-9_]+)/gi;
    while ((match = paypalRegex.exec(cleanedText)) !== null) {
      handles.push({ provider: 'PayPal', identifier: match[1] });
    }

    // Bakong / KHQR mentions
    if (/bakong|khqr|បាគង/i.test(deobfText)) {
      handles.push({ provider: 'Bakong', identifier: 'KHQR/Bakong Payment' });
    }

    return handles;
  }

  /**
   * Extracts social messaging handles (@telegram, WhatsApp links, Messenger)
   */
  private extractSocialHandles(text: string): SocialHandleEntity[] {
    const handles: SocialHandleEntity[] = [];

    // Telegram handle: @username or t.me/username
    const teleHandleRegex = /@([a-zA-Z0-9_]{4,32})\b/g;
    let match;
    while ((match = teleHandleRegex.exec(text)) !== null) {
      handles.push({ platform: 'telegram', handle: match[0] });
    }

    const teleLinkRegex = /(?:t\.me|telegram\.me)\/([a-zA-Z0-9_]{4,32})/gi;
    while ((match = teleLinkRegex.exec(text)) !== null) {
      handles.push({ platform: 'telegram', handle: `@${match[1]}` });
    }

    // WhatsApp link: wa.me/123456
    const waLinkRegex = /(?:wa\.me|chat\.whatsapp\.com)\/([a-zA-Z0-9_]+)/gi;
    while ((match = waLinkRegex.exec(text)) !== null) {
      handles.push({ platform: 'whatsapp', handle: match[0] });
    }

    // Messenger link: m.me/username
    const messengerRegex = /m\.me\/([a-zA-Z0-9_.]+)/gi;
    while ((match = messengerRegex.exec(text)) !== null) {
      handles.push({ platform: 'messenger', handle: match[1] });
    }

    return handles;
  }

  /**
   * Extracts recognized brand and authority mentions
   */
  private extractBrands(text: string): string[] {
    const brandsFound = new Set<string>();
    for (const brand of EntityExtractor.RECOGNIZED_BRANDS) {
      if (brand.regex.test(text)) {
        brandsFound.add(brand.name);
      }
    }
    return Array.from(brandsFound);
  }

  /**
   * Extracts requested sensitive credentials, documents, or remote tools
   */
  private extractRequestedCredentials(deobfText: string): string[] {
    const requested = new Set<string>();

    if (/\b(otp|one-time password|verification code|6-digit code|កូដ otp|លេខកូដ)\b/i.test(deobfText)) {
      requested.add('OTP / One-Time Password');
    }
    if (/\b(password|passcode|secret password|ពាក្យសម្ងាត់)\b/i.test(deobfText)) {
      requested.add('Account Password');
    }
    if (/\b(pin|pin code|atm pin|4-digit pin|លេខសម្ងាត់ pin)\b/i.test(deobfText)) {
      requested.add('PIN Code');
    }
    if (/\b(cvv|cvc|card number|expiration date|credit card|debit card|លេខកាត)\b/i.test(deobfText)) {
      requested.add('Banking / Card Details');
    }
    if (/\b(id card|passport|national id|selfie with id|national identity|អត្តសញ្ញាណប័ណ្ណ|លិខិតឆ្លងដែន)\b/i.test(deobfText)) {
      requested.add('Government Identity Document');
    }
    if (/\b(anydesk|teamviewer|quicksupport|ultraviewer|remote control)\b/i.test(deobfText)) {
      requested.add('Remote Access Software');
    }
    if (/\b(download apk|install app|install profile|download exe|\.apk|\.exe)\b/i.test(deobfText)) {
      requested.add('Suspicious Software / APK Download');
    }

    return Array.from(requested);
  }
}

export const entityExtractor = new EntityExtractor();
