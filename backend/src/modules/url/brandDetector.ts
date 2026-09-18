import { BrandImpersonationMatch } from './types';
import { urlNormalizer } from './urlNormalizer';

export interface TargetBrandConfig {
  key: string;
  name: string;
  category: 'banking' | 'government' | 'shipping' | 'tech' | 'crypto' | 'social';
  legitimateDomains: string[];
  keywords?: string[];
}

export const TARGET_BRANDS: TargetBrandConfig[] = [
  // 1. Cambodian Financial Institutions & Banks
  {
    key: 'ababank',
    name: 'ABA Bank',
    category: 'banking',
    legitimateDomains: ['ababank.com', 'ababank.com.kh'],
    keywords: ['aba', 'ababank'],
  },
  {
    key: 'wingbank',
    name: 'Wing Bank',
    category: 'banking',
    legitimateDomains: ['wingmoney.com', 'wingbank.com.kh'],
    keywords: ['wing', 'wingbank', 'wingmoney'],
  },
  {
    key: 'acleda',
    name: 'ACLEDA Bank',
    category: 'banking',
    legitimateDomains: ['acledabank.com.kh', 'acledabank.com'],
    keywords: ['acleda', 'acledabank'],
  },
  {
    key: 'canadiabank',
    name: 'Canadia Bank',
    category: 'banking',
    legitimateDomains: ['canadiabank.com.kh', 'canadiabank.com'],
    keywords: ['canadia', 'canadiabank'],
  },
  {
    key: 'sathapana',
    name: 'Sathapana Bank',
    category: 'banking',
    legitimateDomains: ['sathapana.com.kh'],
    keywords: ['sathapana'],
  },
  {
    key: 'princebank',
    name: 'Prince Bank',
    category: 'banking',
    legitimateDomains: ['princebank.com.kh'],
    keywords: ['princebank'],
  },
  {
    key: 'bakong',
    name: 'NBC / Bakong',
    category: 'banking',
    legitimateDomains: ['bakong.nbc.gov.kh', 'nbc.gov.kh', 'nbc.org.kh'],
    keywords: ['bakong', 'nbc'],
  },
  {
    key: 'pipay',
    name: 'Pi Pay',
    category: 'banking',
    legitimateDomains: ['pipay.com'],
    keywords: ['pipay'],
  },

  // 2. Cambodian Government, Utilities & Institutions
  {
    key: 'gdt',
    name: 'General Department of Taxation (GDT)',
    category: 'government',
    legitimateDomains: ['tax.gov.kh'],
    keywords: ['gdt', 'taxgov', 'taxationkh'],
  },
  {
    key: 'cambodiapost',
    name: 'Cambodia Post',
    category: 'shipping',
    legitimateDomains: ['cambodiapost.post', 'cambodiapost.com.kh'],
    keywords: ['cambodiapost', 'campost'],
  },
  {
    key: 'policekh',
    name: 'Cambodian National Police',
    category: 'government',
    legitimateDomains: ['police.gov.kh'],
    keywords: ['nationalpolice', 'cambodianpolice'],
  },

  // 3. Global Banking & FinTech
  {
    key: 'paypal',
    name: 'PayPal',
    category: 'banking',
    legitimateDomains: ['paypal.com', 'paypal.me'],
    keywords: ['paypal'],
  },
  {
    key: 'chase',
    name: 'Chase Bank',
    category: 'banking',
    legitimateDomains: ['chase.com', 'jpmorganchase.com'],
  },
  {
    key: 'wellsfargo',
    name: 'Wells Fargo',
    category: 'banking',
    legitimateDomains: ['wellsfargo.com'],
  },
  {
    key: 'bankofamerica',
    name: 'Bank of America',
    category: 'banking',
    legitimateDomains: ['bankofamerica.com', 'bofa.com'],
    keywords: ['bofa'],
  },
  {
    key: 'stripe',
    name: 'Stripe',
    category: 'banking',
    legitimateDomains: ['stripe.com'],
  },
  {
    key: 'revolut',
    name: 'Revolut',
    category: 'banking',
    legitimateDomains: ['revolut.com'],
  },

  // 4. Shipping & Logistics
  {
    key: 'dhl',
    name: 'DHL Express',
    category: 'shipping',
    legitimateDomains: ['dhl.com', 'dhl.com.kh'],
    keywords: ['dhl'],
  },
  {
    key: 'fedex',
    name: 'FedEx',
    category: 'shipping',
    legitimateDomains: ['fedex.com'],
    keywords: ['fedex'],
  },
  {
    key: 'ups',
    name: 'UPS',
    category: 'shipping',
    legitimateDomains: ['ups.com'],
    keywords: ['ups'],
  },
  {
    key: 'jtexpress',
    name: 'J&T Express',
    category: 'shipping',
    legitimateDomains: ['jtexpress.com.kh', 'jtexpress.com'],
    keywords: ['jtexpress'],
  },

  // 5. Big Tech & Cloud
  {
    key: 'apple',
    name: 'Apple',
    category: 'tech',
    legitimateDomains: ['apple.com', 'icloud.com'],
  },
  {
    key: 'google',
    name: 'Google',
    category: 'tech',
    legitimateDomains: ['google.com', 'google.com.kh', 'gmail.com', 'accounts.google.com'],
  },
  {
    key: 'microsoft',
    name: 'Microsoft',
    category: 'tech',
    legitimateDomains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
  },
  {
    key: 'netflix',
    name: 'Netflix',
    category: 'tech',
    legitimateDomains: ['netflix.com'],
  },
  {
    key: 'amazon',
    name: 'Amazon',
    category: 'tech',
    legitimateDomains: ['amazon.com', 'aws.amazon.com'],
  },

  // 6. Social & Messaging
  {
    key: 'facebook',
    name: 'Facebook / Meta',
    category: 'social',
    legitimateDomains: ['facebook.com', 'fb.com', 'meta.com'],
  },
  {
    key: 'instagram',
    name: 'Instagram',
    category: 'social',
    legitimateDomains: ['instagram.com'],
  },
  {
    key: 'telegram',
    name: 'Telegram',
    category: 'social',
    legitimateDomains: ['telegram.org', 't.me'],
  },
  {
    key: 'whatsapp',
    name: 'WhatsApp',
    category: 'social',
    legitimateDomains: ['whatsapp.com', 'wa.me'],
  },

  // 7. Crypto & Web3
  {
    key: 'binance',
    name: 'Binance',
    category: 'crypto',
    legitimateDomains: ['binance.com', 'binance.org'],
  },
  {
    key: 'coinbase',
    name: 'Coinbase',
    category: 'crypto',
    legitimateDomains: ['coinbase.com'],
  },
  {
    key: 'metamask',
    name: 'MetaMask',
    category: 'crypto',
    legitimateDomains: ['metamask.io'],
  },
  {
    key: 'kraken',
    name: 'Kraken',
    category: 'crypto',
    legitimateDomains: ['kraken.com'],
  },
  {
    key: 'ledger',
    name: 'Ledger',
    category: 'crypto',
    legitimateDomains: ['ledger.com'],
  },
];

const COMPOUND_CCTLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
  'com.kh', 'org.kh', 'gov.kh', 'edu.kh', 'net.kh',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp',
  'com.sg', 'edu.sg', 'gov.sg',
  'co.in', 'net.in', 'org.in', 'gen.in',
  'com.br', 'net.br', 'org.br',
  'com.mx', 'org.mx', 'gob.mx',
]);

const COMBISQUATTING_KEYWORDS = [
  'security', 'secure', 'login', 'signin', 'verify', 'verification', 'update',
  'support', 'service', 'account', 'portal', 'alert', 'auth', 'recovery', 'help',
  'online', 'banking', 'wallet', 'claim', 'gift', 'pay', 'center', 'team',
  'parcel', 'delivery', 'tracking', 'package', 'customs', 'fee', 'branch',
  'khqr', 'mobile', 'app', 'download', 'statement', 'confirm', 'customer', 'post'
];

/**
 * Computes the Levenshtein edit distance between two strings.
 */
export function calculateLevenshteinDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix: number[][] = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Extracts the base registered domain and subdomain components from a hostname,
 * correctly accounting for compound ccTLDs like .co.uk and .com.kh.
 */
export function extractDomainParts(hostname: string): {
  baseDomain: string;
  sld: string;
  subdomain: string;
  subdomains: string[];
  tld: string;
} {
  const cleanHost = hostname.toLowerCase().trim();
  const parts = cleanHost.split('.');

  if (parts.length <= 1) {
    return {
      baseDomain: cleanHost,
      sld: cleanHost,
      subdomain: '',
      subdomains: [],
      tld: '',
    };
  }

  if (parts.length === 2) {
    return {
      baseDomain: cleanHost,
      sld: parts[0],
      subdomain: '',
      subdomains: [],
      tld: parts[1],
    };
  }

  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  let baseDomain = '';
  let sld = '';
  let subdomains: string[] = [];

  if (COMPOUND_CCTLDS.has(lastTwo) && parts.length >= 3) {
    baseDomain = parts.slice(-3).join('.');
    sld = parts[parts.length - 3];
    subdomains = parts.slice(0, -3);
  } else {
    baseDomain = parts.slice(-2).join('.');
    sld = parts[parts.length - 2];
    subdomains = parts.slice(0, -2);
  }

  return {
    baseDomain,
    sld,
    subdomain: subdomains.join('.'),
    subdomains,
    tld: parts[parts.length - 1],
  };
}

/**
 * Checks if a hostname is legitimately owned by the target brand.
 */
export function isLegitimateBrandDomain(hostname: string, brand: TargetBrandConfig): boolean {
  const cleanHost = hostname.toLowerCase().trim();
  const { baseDomain, sld } = extractDomainParts(cleanHost);

  for (const legit of brand.legitimateDomains) {
    if (baseDomain === legit || cleanHost === legit || cleanHost.endsWith(`.${legit}`)) {
      return true;
    }
  }

  // Support legitimate ccTLD country branches (e.g. google.com.kh, paypal.co.uk)
  const brandKeys = [brand.key, ...(brand.keywords || [])];
  for (const bKey of brandKeys) {
    if (sld === bKey) {
      if (brand.legitimateDomains.some((d) => d.includes(bKey))) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Performs algorithmic brand impersonation, lookalike, and typosquatting analysis.
 */
export function detectBrandImpersonation(hostname: string): BrandImpersonationMatch {
  const cleanHost = hostname.toLowerCase().trim();
  const { baseDomain, sld, subdomains } = extractDomainParts(cleanHost);

  // 1. Homoglyph / Punycode check (e.g. xn--pypal-... containing Cyrillic / Greek characters)
  if (cleanHost.startsWith('xn--') || cleanHost.includes('.xn--')) {
    for (const brand of TARGET_BRANDS) {
      if (cleanHost.includes(brand.key)) {
        return {
          detected: true,
          targetedBrand: brand.name,
          category: brand.category,
          impersonationType: 'homoglyph',
          matchedHostname: cleanHost,
          baseDomain,
          similarityScore: 95,
          description: `Punycode homoglyph domain disguising brand '${brand.name}' using internationalized characters.`,
        };
      }
    }
    return {
      detected: true,
      targetedBrand: 'Unknown Brand',
      impersonationType: 'homoglyph',
      matchedHostname: cleanHost,
      baseDomain,
      similarityScore: 85,
      description: `Internationalized Domain Name (Punycode xn--) used in hostname, commonly used for look-alike spoofing.`,
    };
  }

  // 2. Homoglyph mapping on Unicode/Latin characters
  const homoglyphMapped = urlNormalizer.mapHomoglyphs(cleanHost);
  if (homoglyphMapped !== cleanHost) {
    for (const brand of TARGET_BRANDS) {
      if (homoglyphMapped.includes(brand.key) && !isLegitimateBrandDomain(cleanHost, brand)) {
        return {
          detected: true,
          targetedBrand: brand.name,
          category: brand.category,
          impersonationType: 'homoglyph',
          matchedHostname: cleanHost,
          baseDomain,
          similarityScore: 96,
          description: `Mixed-script homoglyph substitution detected: '${cleanHost}' visually impersonates '${brand.name}'.`,
        };
      }
    }
  }

  // Sort brands so longer/more specific brand keys match first (e.g. 'acledabank' or 'canadiabank' before 'aba')
  const sortedBrands = [...TARGET_BRANDS].sort((a, b) => b.key.length - a.key.length);

  for (const brand of sortedBrands) {
    if (isLegitimateBrandDomain(cleanHost, brand)) {
      continue;
    }

    const brandKeys = [brand.key, ...(brand.keywords || [])];

    for (const bKey of brandKeys) {
      // Create precise boundary matcher for short keys (<= 3 chars, e.g. 'aba', 'nbc', 'gdt', 'ups')
      // to avoid matching 'aba' inside 'acledabank' or 'canadiabank'
      const isShortKey = bKey.length <= 3;
      const bKeyBoundaryRegex = isShortKey
        ? new RegExp(`(^|[-_.0-9])${bKey}([-_.0-9]|$)`, 'i')
        : new RegExp(bKey, 'i');

      // 3. Subdomain Spoofing / Brand Injection
      const brandInSubdomain = subdomains.some(
        (sub) => sub === bKey || sub === `${bKey}.com` || sub.startsWith(`${bKey}-`) || sub.endsWith(`-${bKey}`)
      );
      if (brandInSubdomain && sld !== bKey) {
        return {
          detected: true,
          targetedBrand: brand.name,
          category: brand.category,
          impersonationType: 'subdomain_spoof',
          matchedHostname: cleanHost,
          baseDomain,
          similarityScore: 90,
          description: `Brand '${brand.name}' injected into subdomains of an unrelated domain (${baseDomain}).`,
        };
      }

      if (bKeyBoundaryRegex.test(cleanHost) && !bKeyBoundaryRegex.test(baseDomain)) {
        return {
          detected: true,
          targetedBrand: brand.name,
          category: brand.category,
          impersonationType: 'subdomain_spoof',
          matchedHostname: cleanHost,
          baseDomain,
          similarityScore: 88,
          description: `Hostname contains brand '${brand.name}' while root domain is '${baseDomain}'.`,
        };
      }

      // 4. Combisquatting (Brand paired with action/security keywords in base domain SLD)
      const hasBrandInSld = isShortKey ? bKeyBoundaryRegex.test(sld) : sld.includes(bKey);
      const hasCombisquattingPattern =
        hasBrandInSld &&
        sld !== bKey &&
        (sld.includes('-') || COMBISQUATTING_KEYWORDS.some((kw) => sld.includes(kw)));

      if (hasCombisquattingPattern) {
        return {
          detected: true,
          targetedBrand: brand.name,
          category: brand.category,
          impersonationType: 'combisquatting',
          matchedHostname: cleanHost,
          baseDomain,
          similarityScore: 92,
          description: `Combisquatting detected: '${sld}' couples brand '${brand.name}' with deceptive action keywords.`,
        };
      }

      // 5. Visual Lookalike Transliteration Check
      const tokensToCheck = Array.from(new Set([sld, ...sld.split(/[-_.]/).filter(Boolean)]));

      for (const tok of tokensToCheck) {
        const looksLikePaypal = tok === 'paypai' || tok === 'paypa1';
        const looksLikeAmazon = tok.replace(/rn/g, 'm') === 'amazon';
        const looksLikeWhatsapp = tok.replace(/vv/g, 'w') === 'whatsapp';
        const looksLikeGoogle = tok === 'googic' || tok === 'g00gle';

        if ((looksLikePaypal && bKey === 'paypal') ||
            (looksLikeAmazon && bKey === 'amazon') ||
            (looksLikeWhatsapp && bKey === 'whatsapp') ||
            (looksLikeGoogle && bKey === 'google')) {
          return {
            detected: true,
            targetedBrand: brand.name,
            category: brand.category,
            impersonationType: 'typosquatting',
            matchedHostname: cleanHost,
            baseDomain,
            levenshteinDistance: 1,
            similarityScore: 90,
            lookalikeSubstitution: tok,
            description: `Visual lookalike/typosquatting detected: '${tok}' deceptive copy of '${brand.name}'.`,
          };
        }

        // 6. Typosquatting (Levenshtein Edit Distance)
        if (tok.length >= 3 && Math.abs(tok.length - bKey.length) <= 2) {
          const distance = calculateLevenshteinDistance(tok, bKey);

          const isTyposquatting = distance === 1 || (distance === 2 && bKey.length >= 6);

          if (isTyposquatting && tok !== bKey) {
            const maxLen = Math.max(tok.length, bKey.length);
            const similarity = Math.round(((maxLen - distance) / maxLen) * 100);

            return {
              detected: true,
              targetedBrand: brand.name,
              category: brand.category,
              impersonationType: 'typosquatting',
              matchedHostname: cleanHost,
              baseDomain,
              levenshteinDistance: distance,
              similarityScore: similarity,
              description: `Typosquatting detected: '${tok}' is visually similar to '${brand.name}' (edit distance: ${distance}, similarity: ${similarity}%).`,
            };
          }
        }
      }
    }
  }

  return {
    detected: false,
  };
}
