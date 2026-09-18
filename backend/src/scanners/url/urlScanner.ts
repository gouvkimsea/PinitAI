import axios, { AxiosResponse } from 'axios';
import { DetectionItem, UrlScanMetadata } from '../../types';
import { validateUrlForSsrf } from './ssrfGuard';
import { logger } from '../../utils/logger';
import { httpAgent, httpsAgent } from '../../utils/httpConnectionPool';

export interface UrlAnalysisResult {
  metadata: UrlScanMetadata;
  detections: DetectionItem[];
}

const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'work', 'click',
  'country', 'stream', 'download', 'racing', 'win', 'vip', 'cam', 'quest'
]);

const TARGETED_BRANDS = [
  'paypal', 'apple', 'chase', 'wellsfargo', 'bankofamerica', 'google',
  'microsoft', 'netflix', 'amazon', 'dhl', 'fedex', 'usps', 'binance',
  'coinbase', 'metamask', 'telegram', 'whatsapp', 'facebook', 'instagram'
];

const PHISHING_KEYWORDS = [
  'verify', 'account', 'login', 'signin', 'suspended', 'unlock',
  'security-alert', 'wallet-connect', 'claim-airdrop', 'confirm-identity',
  'banking-update', 'billing-issue', 'password-reset', 'secure-portal'
];

/**
 * Normalizes a URL for consistent analysis and deduplication.
 */
export function normalizeUrl(rawUrl: string): string {
  let formatted = rawUrl.trim();
  if (!/^https?:\/\//i.test(formatted)) {
    formatted = `https://${formatted}`;
  }

  try {
    const parsed = new URL(formatted);
    // Lowercase host
    parsed.hostname = parsed.hostname.toLowerCase();
    // Remove default ports
    if ((parsed.protocol === 'http:' && parsed.port === '80') || (parsed.protocol === 'https:' && parsed.port === '443')) {
      parsed.port = '';
    }
    let normalized = parsed.toString();
    if (normalized.endsWith('/') && (parsed.pathname === '/' || parsed.pathname === '') && !parsed.search && !parsed.hash) {
      normalized = normalized.slice(0, -1);
    }
    return normalized;
  } catch {
    return rawUrl;
  }
}

/**
 * Analyzes a URL for malware, phishing, SSRF, and suspicious anomalies.
 */
export async function analyzeUrl(rawUrl: string): Promise<UrlAnalysisResult> {
  const detections: DetectionItem[] = [];
  const normalized = normalizeUrl(rawUrl);

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    detections.push({
      engine: 'URLValidator',
      category: 'invalid_format',
      severity: 'high',
      ruleId: 'URL-ERR-001',
      title: 'Malformed URL',
      description: 'The provided target string cannot be parsed as a valid URL.',
    });

    return {
      metadata: {
        url: rawUrl,
        normalizedUrl: rawUrl,
        domain: '',
        isHttps: false,
        hasRedirects: false,
        redirectCount: 0,
        redirectChain: [],
        isPunycode: false,
        suspiciousKeywordsFound: [],
      },
      detections,
    };
  }

  const domain = parsed.hostname;
  const isHttps = parsed.protocol === 'https:';
  const isPunycode = domain.startsWith('xn--') || domain.includes('.xn--');
  const tld = domain.split('.').pop()?.toLowerCase() || '';

  // 1. SSRF Check
  const ssrfCheck = await validateUrlForSsrf(normalized);
  if (!ssrfCheck.isSafe) {
    logger.trackSuspiciousActivity({
      activityType: 'SSRF_ATTEMPT',
      severity: 'CRITICAL',
      details: {
        url: rawUrl,
        normalizedUrl: normalized,
        reason: ssrfCheck.blockedReason,
        resolvedIp: ssrfCheck.resolvedIp,
      },
    });

    detections.push({
      engine: 'SSRFGuard',
      category: 'ssrf_hazard',
      severity: 'critical',
      ruleId: 'SSRF-001',
      title: 'Severe Security Risk: Internal Network or Metadata Target (SSRF)',
      description: ssrfCheck.blockedReason || 'URL resolves to private/internal network addresses.',
      details: { resolvedIp: ssrfCheck.resolvedIp },
    });

    return {
      metadata: {
        url: rawUrl,
        normalizedUrl: normalized,
        domain,
        ipAddress: ssrfCheck.resolvedIp,
        isHttps,
        hasRedirects: false,
        redirectCount: 0,
        redirectChain: [],
        isPunycode,
        suspiciousKeywordsFound: [],
      },
      detections,
    };
  }

  // 2. HTTPS Check
  if (!isHttps) {
    detections.push({
      engine: 'URLSecurity',
      category: 'transport_security',
      severity: 'medium',
      ruleId: 'URL-SEC-001',
      title: 'Insecure Plain HTTP Protocol',
      description: 'The URL uses unencrypted HTTP. Legitimate financial, login, and authentication portals require HTTPS.',
    });
  }

  // 3. Userinfo (@ symbol) credential exploit
  if (parsed.username || parsed.password) {
    detections.push({
      engine: 'URLSecurity',
      category: 'deceptive_url',
      severity: 'critical',
      ruleId: 'URL-DEC-002',
      title: 'Embedded Credentials / Phishing Redirect Pattern',
      description: 'URL includes user authentication symbols (@) to disguise the actual destination domain from users.',
    });
  }

  // 4. Punycode / Homoglyph Attack
  if (isPunycode) {
    detections.push({
      engine: 'URLSecurity',
      category: 'homoglyph_attack',
      severity: 'high',
      ruleId: 'URL-HOM-003',
      title: 'Internationalized Domain (Punycode / Lookalike)',
      description: 'Domain uses Punycode (xn--). Often used to spoof major brand names with visually identical non-Latin characters (IDN Homograph Attack).',
    });
  }

  // 5. High-Risk TLD
  if (HIGH_RISK_TLDS.has(tld)) {
    detections.push({
      engine: 'URLSecurity',
      category: 'suspicious_tld',
      severity: 'medium',
      ruleId: 'URL-TLD-004',
      title: 'High-Risk Top-Level Domain',
      description: `Domain uses top-level domain (.${tld}) with disproportionately high abuse and phishing rates according to threat intelligence telemetry.`,
    });
  }

  // 6. Brand Impersonation in Subdomains
  const extractBaseDomain = (d: string): string => {
    const parts = d.split('.');
    if (parts.length <= 2) return d;
    const secondLevelTlds = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil']);
    const tldPart = parts[parts.length - 1];
    const sldPart = parts[parts.length - 2];
    if (tldPart.length === 2 && secondLevelTlds.has(sldPart) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  };

  const baseDomain = extractBaseDomain(domain);
  const suspiciousKeywordsFound: string[] = [];

  for (const brand of TARGETED_BRANDS) {
    // If brand appears in domain, check if it is the genuine base domain
    if (domain.includes(brand) && !baseDomain.includes(brand)) {
      detections.push({
        engine: 'URLPhishingEngine',
        category: 'brand_impersonation',
        severity: 'critical',
        ruleId: 'URL-BRD-005',
        title: `Brand Impersonation Signal: ${brand.toUpperCase()}`,
        description: `The URL contains the brand '${brand}' inside subdomains or paths of an unrelated domain (${domain}). Typical of credential harvesting.`,
        details: { targetedBrand: brand, actualDomain: domain },
      });
    }
  }

  // 7. Phishing keywords in path or query
  const fullPathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  for (const keyword of PHISHING_KEYWORDS) {
    if (fullPathAndQuery.includes(keyword)) {
      suspiciousKeywordsFound.push(keyword);
    }
  }

  if (suspiciousKeywordsFound.length >= 2) {
    detections.push({
      engine: 'URLPhishingEngine',
      category: 'phishing_pattern',
      severity: 'high',
      ruleId: 'URL-KW-006',
      title: 'Suspicious Credential Action Keywords',
      description: `URL contains multiple high-risk keywords in path: [${suspiciousKeywordsFound.join(', ')}].`,
      details: { keywords: suspiciousKeywordsFound },
    });
  }

  // 8. Safe Isolated HTTP Probing (Hop-by-hop redirect verification with SSRF guard)
  let hasRedirects = false;
  let redirectCount = 0;
  const redirectChain: string[] = [normalized];
  let finalStatusCode: number | undefined;

  try {
    let currentUrl = normalized;
    const maxHops = 5;

    for (let hop = 0; hop < maxHops; hop++) {
      const probeResponse: AxiosResponse = await axios.get(currentUrl, {
        httpAgent,
        httpsAgent,
        timeout: 2500,
        maxRedirects: 0, // Stop Axios from blindly following redirects before checking SSRF
        maxBodyLength: 512 * 1024,
        maxContentLength: 512 * 1024,
        validateStatus: () => true,
        headers: {
          'User-Agent': 'PinIt-Security-Scanner/1.0 (+https://pinit.security/bot)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      finalStatusCode = probeResponse.status;

      // Check if redirect response (301, 302, 303, 307, 308)
      if (
        [301, 302, 303, 307, 308].includes(probeResponse.status) &&
        probeResponse.headers.location
      ) {
        let redirectTarget: string;
        try {
          redirectTarget = new URL(probeResponse.headers.location, currentUrl).toString();
        } catch {
          break;
        }

        hasRedirects = true;
        redirectCount++;
        redirectChain.push(redirectTarget);

        // Enforce SSRF validation on the destination BEFORE following the redirect
        const hopSsrf = await validateUrlForSsrf(redirectTarget);
        if (!hopSsrf.isSafe) {
          detections.push({
            engine: 'SSRFGuard',
            category: 'redirect_ssrf',
            severity: 'critical',
            ruleId: 'SSRF-002',
            title: 'Malicious Redirect to Internal / Metadata Service',
            description: `The URL attempts a redirect to a forbidden internal destination: ${redirectTarget}. Blocked for SSRF defense.`,
            details: { blockedTarget: redirectTarget, reason: hopSsrf.blockedReason },
          });
          // Stop following redirect to protect internal network
          break;
        }

        currentUrl = redirectTarget;
      } else {
        // Not a redirect, reached terminal response
        break;
      }
    }
  } catch (err) {
    logger.debug('URL network probe failed or timed out', { url: normalized, error: (err as Error).message });
  }

  return {
    metadata: {
      url: rawUrl,
      normalizedUrl: normalized,
      domain,
      ipAddress: ssrfCheck.resolvedIp,
      isHttps,
      hasRedirects,
      redirectCount,
      redirectChain,
      statusCode: finalStatusCode,
      isPunycode,
      suspiciousKeywordsFound,
    },
    detections,
  };
}
