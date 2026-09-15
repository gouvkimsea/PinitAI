import { BrandImpersonationMatch } from './types';

export interface TargetBrandConfig {
  key: string;
  name: string;
  category: 'banking' | 'tech' | 'crypto' | 'shipping' | 'social';
  legitimateDomains: string[];
  keywords?: string[];
}

export const TARGET_BRANDS: TargetBrandConfig[] = [
  // Banking & FinTech
  {
    key: 'paypal',
    name: 'PayPal',
    category: 'banking',
    legitimateDomains: ['paypal.com', 'paypal.me'],
  },
  {
    key: 'ababank',
    name: 'ABA Bank',
    category: 'banking',
    legitimateDomains: ['ababank.com', 'ababank.com.kh'],
    keywords: ['aba'],
  },
  {
    key: 'acleda',
    name: 'ACLEDA Bank',
    category: 'banking',
    legitimateDomains: ['acledabank.com.kh', 'acledabank.com'],
  },
  {
    key: 'wingbank',
    name: 'Wing Bank',
    category: 'banking',
    legitimateDomains: ['wingmoney.com', 'wingbank.com.kh'],
    keywords: ['wing'],
  },
  {
    key: 'canadiabank',
    name: 'Canadia Bank',
    category: 'banking',
    legitimateDomains: ['canadiabank.com.kh', 'canadiabank.com'],
    keywords: ['canadia'],
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

  // Big Tech & Cloud
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
    legitimateDomains: ['google.com', 'gmail.com', 'accounts.google.com'],
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

  // Social & Messaging
  {
    key: 'facebook',
    name: 'Facebook',
    category: 'social',
    legitimateDomains: ['facebook.com', 'fb.com'],
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
    legitimateDomains: ['whatsapp.com'],
  },

  // Crypto & Web3
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

  // Shipping & Logistics
  {
    key: 'dhl',
    name: 'DHL Express',
    category: 'shipping',
    legitimateDomains: ['dhl.com'],
  },
  {
    key: 'fedex',
    name: 'FedEx',
    category: 'shipping',
    legitimateDomains: ['fedex.com'],
  },
  {
    key: 'usps',
    name: 'USPS',
    category: 'shipping',
    legitimateDomains: ['usps.com'],
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
  const { baseDomain } = extractDomainParts(cleanHost);

  for (const legit of brand.legitimateDomains) {
    if (baseDomain === legit || cleanHost === legit || cleanHost.endsWith(`.${legit}`)) {
      return true;
    }
  }

  // Also support legitimate country extensions e.g. paypal.co.uk, amazon.de, google.com.kh
  const sld = extractDomainParts(cleanHost).sld;
  if (sld === brand.key) {
    // If the registered SLD matches brand exactly and legit domains include standard .com
    const standardCom = `${brand.key}.com`;
    if (brand.legitimateDomains.includes(standardCom)) {
      return true;
    }
  }

  return false;
}

/**
 * Performs algorithmic brand impersonation and typosquatting analysis.
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

  for (const brand of TARGET_BRANDS) {
    // If this is legitimate domain of the brand, skip
    if (isLegitimateBrandDomain(cleanHost, brand)) {
      continue;
    }

    const brandKeys = [brand.key, ...(brand.keywords || [])];

    for (const bKey of brandKeys) {
      // 2. Subdomain Spoofing / Brand Injection
      // e.g. paypal.com.verify-user.attacker.com or chase.secure-login.xyz
      const brandInSubdomain = subdomains.some(
        (sub) => sub === bKey || sub === `${bKey}.com` || sub.startsWith(`${bKey}-`) || sub.endsWith(`-${bKey}`)
      );
      if (brandInSubdomain && sld !== bKey) {
        return {
          detected: true,
          targetedBrand: brand.name,
          impersonationType: 'subdomain_spoof',
          matchedHostname: cleanHost,
          baseDomain,
          similarityScore: 90,
          description: `Brand '${brand.name}' injected into subdomains of an unrelated domain (${baseDomain}).`,
        };
      }

      // Also check if full hostname contains the brand but the base domain is completely different
      if (cleanHost.includes(bKey) && !baseDomain.includes(bKey)) {
        return {
          detected: true,
          targetedBrand: brand.name,
          impersonationType: 'subdomain_spoof',
          matchedHostname: cleanHost,
          baseDomain,
          similarityScore: 88,
          description: `Hostname contains brand '${brand.name}' while root domain is '${baseDomain}'.`,
        };
      }

      // 3. Combisquatting (Brand paired with security/action keywords in base domain SLD)
      // e.g. paypal-security.com, login-apple.com, binance-wallet.com
      const COMBISQUATTING_KEYWORDS = [
        'security', 'secure', 'login', 'signin', 'verify', 'verification', 'update',
        'support', 'service', 'account', 'portal', 'alert', 'auth', 'recovery', 'help',
        'online', 'banking', 'wallet', 'claim', 'gift', 'pay', 'center', 'team'
      ];

      const hasCombisquattingPattern =
        sld.includes(bKey) &&
        sld !== bKey &&
        (sld.includes('-') || COMBISQUATTING_KEYWORDS.some((kw) => sld.includes(kw)));

      if (hasCombisquattingPattern) {
        return {
          detected: true,
          targetedBrand: brand.name,
          impersonationType: 'combisquatting',
          matchedHostname: cleanHost,
          baseDomain,
          similarityScore: 92,
          description: `Combisquatting detected: '${sld}' couples brand '${brand.name}' with deceptive action keywords.`,
        };
      }

      // 4. Typosquatting (Levenshtein Edit Distance)
      // Check both the entire SLD and individual tokens within hyphenated SLDs (e.g. paypa1, paypa1-account-update)
      const tokensToCheck = Array.from(new Set([sld, ...sld.split(/[-_.]/).filter(Boolean)]));

      for (const tok of tokensToCheck) {
        if (tok.length >= 3 && Math.abs(tok.length - bKey.length) <= 2) {
          const distance = calculateLevenshteinDistance(tok, bKey);

          // Typosquatting condition:
          // - Distance is 1 for any brand
          // - Distance is 2 for brands with length >= 6 (e.g. binance, paypal, netflix)
          const isTyposquatting = distance === 1 || (distance === 2 && bKey.length >= 6);

          if (isTyposquatting && tok !== bKey) {
            const maxLen = Math.max(tok.length, bKey.length);
            const similarity = Math.round(((maxLen - distance) / maxLen) * 100);

            return {
              detected: true,
              targetedBrand: brand.name,
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
