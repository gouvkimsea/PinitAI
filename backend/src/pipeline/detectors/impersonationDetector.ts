import { IDetector, InputType, NormalizedInput, PipelineContext, DetectorResult, DetectorSeverity } from '../types';

interface ImpersonationEntity {
  name: string;
  category: 'FINANCIAL' | 'GOVERNMENT' | 'TECH_BRAND' | 'EXECUTIVE';
  patterns: RegExp[];
  officialDomains?: string[];
}

const MONITORED_ENTITIES: ImpersonationEntity[] = [
  // Cambodian & Regional Financial Institutions
  {
    name: 'ABA Bank',
    category: 'FINANCIAL',
    patterns: [/\baba\s*bank\b/i, /\baba\s*mobile\b/i, /\baba\s*account\b/i, /\baba\s*pay\b/i, /ធនាគារ\s*អេប៊ីអេ/u],
    officialDomains: ['ababank.com', 'ababank.com.kh'],
  },
  {
    name: 'Wing Bank',
    category: 'FINANCIAL',
    patterns: [/\bwing\s*bank\b/i, /\bwing\s*money\b/i, /ធនាគារ\s*វីង/u],
    officialDomains: ['wingmoney.com'],
  },
  {
    name: 'ACLEDA Bank',
    category: 'FINANCIAL',
    patterns: [/\bacleda\s*bank\b/i, /\bacleda\s*mobile\b/i, /ធនាគារ\s*អេស៊ីលីដា/u],
    officialDomains: ['acledabank.com.kh'],
  },
  {
    name: 'Bakong Payment System',
    category: 'FINANCIAL',
    patterns: [/\bbakong\b/i, /បាគង/u],
    officialDomains: ['bakong.nbc.gov.kh'],
  },
  // Global Financial & Crypto Brands
  {
    name: 'PayPal',
    category: 'FINANCIAL',
    patterns: [/\bpaypal\b/i, /\bpay\s*pal\b/i],
    officialDomains: ['paypal.com'],
  },
  {
    name: 'Binance',
    category: 'FINANCIAL',
    patterns: [/\bbinance\b/i, /\bbnb\s*chain\b/i],
    officialDomains: ['binance.com'],
  },
  {
    name: 'Coinbase',
    category: 'FINANCIAL',
    patterns: [/\bcoinbase\b/i],
    officialDomains: ['coinbase.com'],
  },
  {
    name: 'Chase Bank',
    category: 'FINANCIAL',
    patterns: [/\bchase\s*bank\b/i, /\bjpmorgan\b/i],
    officialDomains: ['chase.com'],
  },
  {
    name: 'Generic Bank / Financial Institution Authority',
    category: 'FINANCIAL',
    patterns: [/\b(bank\s*credentials|bank\s*verification|bank\s*security|bank\s*support|bank\s*account\s*suspended)\b/i],
  },
  // Government & Regulatory Authorities
  {
    name: 'National Bank of Cambodia (NBC)',
    category: 'GOVERNMENT',
    patterns: [/\bnational\s*bank\s*of\s*cambodia\b/i, /ធនាគារជាតិនៃកម្ពុជា/u],
    officialDomains: ['nbc.gov.kh'],
  },
  {
    name: 'General Department of Taxation (GDT)',
    category: 'GOVERNMENT',
    patterns: [/\btax\s*department\b/i, /\bgdt\b/i, /អគ្គនាយកដ្ឋានពន្ធដារ/u],
    officialDomains: ['tax.gov.kh'],
  },
  {
    name: 'Police / Law Enforcement Agency',
    category: 'GOVERNMENT',
    patterns: [/\bcyber\s*crime\s*police\b/i, /\binterpol\b/i, /\bfbi\s*agent\b/i, /សមត្ថកិច្ច/u, /នគរបាល/u],
  },
  // Tech & Communication Brands
  {
    name: 'Telegram / Meta / Google Security',
    category: 'TECH_BRAND',
    patterns: [/\btelegram\s*security\b/i, /\bmeta\s*support\b/i, /\bwhatsapp\s*support\b/i, /\bgoogle\s*verification\b/i],
    officialDomains: ['telegram.org', 'meta.com', 'whatsapp.com', 'google.com'],
  },
  // Executive & Corporate Hierarchy
  {
    name: 'Corporate Executive / CEO Urgent Wire',
    category: 'EXECUTIVE',
    patterns: [/\b(i\s*am\s*the\s*ceo|urgent\s*wire\s*transfer|confidential\s*request\s*from\s*ceo)\b/i, /\b(buy\s*apple\s*gift\s*cards\s*for\s*staff)\b/i],
  },
];

export class ImpersonationDetector implements IDetector {
  readonly name = 'impersonation_detector';
  readonly type = 'impersonation' as const;
  readonly enabled = true;

  supports(type: InputType): boolean {
    return type === 'TEXT' || type === 'URL' || type === 'QR';
  }

  async detect(input: NormalizedInput, _context: PipelineContext): Promise<DetectorResult | null> {
    const startTime = Date.now();
    const content = `${input.normalizedText || ''} ${input.raw || ''}`.toLowerCase();
    const targetUrl = input.normalizedUrl || '';
    const indicators: string[] = [];
    let score = 0;
    let detectedEntities: string[] = [];

    let targetHostname = '';
    if (targetUrl) {
      try {
        targetHostname = new URL(targetUrl).hostname.toLowerCase();
      } catch {
        targetHostname = '';
      }
    }

    // 1. Textual Impersonation Analysis
    for (const entity of MONITORED_ENTITIES) {
      // If the URL being analyzed is an official domain of this entity, it is NOT an impersonation
      if (
        targetHostname &&
        entity.officialDomains &&
        entity.officialDomains.some((d) => targetHostname === d || targetHostname.endsWith(`.${d}`))
      ) {
        continue;
      }

      let matched = false;
      for (const pattern of entity.patterns) {
        if (pattern.test(content)) {
          matched = true;
          break;
        }
      }

      if (matched) {
        detectedEntities.push(entity.name);
        if (entity.category === 'GOVERNMENT') {
          score += 45;
          indicators.push(`Government/Regulatory Authority Impersonation: ${entity.name}`);
        } else if (entity.category === 'FINANCIAL') {
          score += 40;
          indicators.push(`Financial Institution / Banking Brand Impersonation: ${entity.name}`);
        } else if (entity.category === 'EXECUTIVE') {
          score += 50;
          indicators.push(`Executive / CEO Urgent Wire Impersonation Scheme`);
        } else {
          score += 30;
          indicators.push(`Recognized Tech Brand / Platform Impersonation: ${entity.name}`);
        }
      }
    }

    // 2. Coercive / Urgent Impersonation Modifiers
    const hasCoercion = /(arrest|lawsuit|suspend|frozen|penalty|warrant|lock\s*your\s*account|បិទគណនី|ជាប់ពន្ធនាគារ)/i.test(content);
    if (detectedEntities.length > 0 && hasCoercion) {
      score += 25;
      indicators.push('Coercive Impersonation: Authority presence coupled with punitive/account suspension threats.');
    }

    // 3. Look-alike / Brand Squatting in URLs
    if (targetUrl) {
      try {
        const parsed = new URL(targetUrl);
        const hostname = parsed.hostname.toLowerCase();

        for (const entity of MONITORED_ENTITIES) {
          if (!entity.officialDomains || entity.officialDomains.length === 0) continue;

          // Check if hostname contains the brand name
          const brandSlug = entity.name.toLowerCase().replace(/[^a-z0-9]/g, '');
          const isOfficial = entity.officialDomains.some((d) => hostname === d || hostname.endsWith(`.${d}`));

          if (!isOfficial && hostname.includes(brandSlug)) {
            score = Math.max(score, 75);
            indicators.push(`Brand Combisquatting Impersonation: Domain "${hostname}" impersonates ${entity.name} but does not belong to verified domains (${entity.officialDomains.join(', ')})`);
          }
        }
      } catch {
        // Invalid URL handled by URL normalizer
      }
    }

    // 4. Score normalisation & confidence
    score = Math.min(100, score);
    const duration = Date.now() - startTime;

    let severity: DetectorSeverity = 'safe';
    if (score >= 80) severity = 'critical';
    else if (score >= 60) severity = 'high';
    else if (score >= 40) severity = 'medium';
    else if (score > 0) severity = 'low';

    const confidence = indicators.length > 0 ? 85 : 60;
    const summary = indicators.length > 0
      ? `Impersonation detector flagged ${indicators.length} entity spoofing indicators (${detectedEntities.join(', ')}).`
      : 'No authority, brand, or executive impersonation patterns detected.';

    return {
      detector_name: this.name,
      detector_type: this.type,
      score,
      severity,
      confidence,
      evidence: {
        summary,
        indicators,
        details: {
          detectedEntities,
          hasCoercionModifier: hasCoercion,
        },
      },
      execution_time_ms: duration,
    };
  }
}
