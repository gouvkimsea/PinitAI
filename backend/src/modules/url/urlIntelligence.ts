import { threatIntel } from '../../scanners/threatIntel/threatIntelProvider';
import { DetectionItem } from '../../types';
import { detectBrandImpersonation, extractDomainParts } from './brandDetector';
import { probeUrlSafely } from './networkProbe';
import { domainAgeService } from './domainAgeService';
import { urlNormalizer, normalizeUrlString } from './urlNormalizer';
import {
  BrandImpersonationMatch,
  DomainAgeInfo,
  NetworkProbeResult,
  StructuralAnalysis,
  TlsInfo,
  ContentSignals,
  UrlIntelligenceResult,
  UrlMetadata,
  UrlThreatIndicators,
} from './types';

// Re-export normalizeUrlString for backward compatibility
export { normalizeUrlString };

const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'work', 'click',
  'country', 'stream', 'download', 'racing', 'win', 'vip', 'cam', 'quest',
  'loan', 'cfd', 'zip', 'mov', 'surf', 'icu', 'fit', 'buzz', 'date', 'faith'
]);

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'cutt.ly', 'rb.gy', 'shorturl.at', 'rebrand.ly', 'tiny.cc', 'clck.ru', 'v.gd',
  's.id', 't.ly'
]);

const CREDENTIAL_PATH_KEYWORDS = [
  'login', 'signin', 'account', 'verify', 'verification', 'security',
  'banking', 'update', 'wallet', 'claim', 'auth', 'authenticate',
  'password', 'reset', 'portal', 'confirm', 'identity', 'unlock', 'kyc',
  'credentials', 'passcode', 'security-check'
];

const PAYMENT_PATH_KEYWORDS = [
  'checkout', 'payment', 'pay', 'transfer', 'wire', 'khqr', 'bakong',
  'invoice', 'billing', 'card', 'deposit', 'withdraw', 'remit', 'topup'
];

const LOGIN_PATH_KEYWORDS = [
  'login', 'signin', 'auth/login', 'portal/login', 'wp-login.php',
  'webmail', 'cpanel', 'oauth/authorize', 'admin/login', 'user/login'
];

const EXECUTABLE_EXTENSIONS = new Set([
  'exe', 'apk', 'scr', 'bat', 'cmd', 'vbs', 'pif', 'jar', 'msi', 'ps1', 'iso', 'hta', 'dmg', 'dll'
]);

const OPEN_REDIRECT_PARAMS = new Set([
  'redirect', 'redirect_to', 'redirect_uri', 'return', 'return_to',
  'url', 'target', 'dest', 'destination', 'next', 'r', 'goto', 'link', 'out'
]);

const SENSITIVE_QUERY_PARAMS = new Set([
  'password', 'pwd', 'pass', 'token', 'otp', 'pin', 'ssn', 'credit_card', 'secret', 'key'
]);

/**
 * Calculates the Shannon entropy of a string (measures randomness/unpredictability).
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

export class UrlIntelligence {
  /**
   * Performs an exhaustive multi-dimensional intelligence scan on a URL across all 25 dimensions.
   */
  async analyze(
    rawUrl: string,
    options: { skipNetworkProbe?: boolean; skipDomainAge?: boolean } = {}
  ): Promise<UrlIntelligenceResult> {
    const norm = urlNormalizer.normalize(rawUrl);
    const detections: DetectionItem[] = [];
    const indicators: string[] = [];
    const riskFactors: string[] = [];
    const safeFactors: string[] = [];

    // Dimension 1 & 2: URL Syntax & Scheme Validation
    if (!norm.isValid) {
      const isDangerousScheme = norm.isDangerousScheme;
      const invalidMetadata: UrlMetadata = {
        rawUrl,
        normalizedUrl: norm.normalizedUrl,
        protocol: isDangerousScheme ? rawUrl.split(':')[0] : '',
        isHttps: false,
        isDangerousScheme,
        schemeViolation: norm.schemeViolation,
        hostname: '',
        domain: '',
        baseDomain: '',
        subdomains: [],
        subdomainCount: 0,
        tld: '',
        pathname: '',
        search: '',
        hash: '',
        isIpAddress: false,
        isObfuscatedIp: false,
        isShortener: false,
        isPunycode: false,
        hasUserinfo: false,
      };

      const emptyStructural: StructuralAnalysis = {
        entropyScore: 0,
        hyphenCount: 0,
        digitRatio: 0,
        subdomainDepth: 0,
        isExcessiveSubdomains: false,
        hasCredentialPath: false,
        credentialKeywordsFound: [],
        hasExecutablePayload: false,
        hasOpenRedirectParam: false,
        openRedirectParamsFound: [],
        hasSensitiveQueryParams: false,
        sensitiveQueryParamsFound: [],
        hasPathTraversal: false,
      };

      const emptyProbe: NetworkProbeResult = {
        probed: false,
        hasRedirects: false,
        redirectCount: 0,
        redirectChain: [],
        crossDomainRedirect: false,
        targetDomainChanged: false,
        ssrfSafe: !isDangerousScheme,
      };

      if (isDangerousScheme) {
        return {
          url: rawUrl,
          normalizedUrl: norm.normalizedUrl,
          compositeScore: 95,
          severity: 'critical',
          confidence: 99,
          threatCategory: 'MALWARE',
          indicators: [norm.schemeViolation || 'Dangerous execution pseudo-scheme detected.'],
          detections: [{
            engine: 'URLSchemeValidator',
            category: 'dangerous_scheme',
            severity: 'critical',
            ruleId: 'URL-SCHEME-001',
            title: 'Dangerous Pseudo-Scheme Execution Target',
            description: norm.schemeViolation || 'Dangerous pseudo-scheme capable of client-side code execution or local file access.',
          }],
          brandImpersonation: { detected: false },
          metadata: invalidMetadata,
          structural: emptyStructural,
          networkProbe: emptyProbe,
          evidence: {
            summary: norm.schemeViolation || 'Dangerous pseudo-scheme detected.',
            indicators: [norm.schemeViolation || 'Dangerous scheme violation'],
            riskFactors: ['Target uses non-web protocol designed for script execution or local resource leakage'],
            safeFactors: [],
            details: {
              metadata: invalidMetadata,
              brandImpersonation: { detected: false },
              structural: emptyStructural,
              networkProbe: emptyProbe,
              threatIntelMatched: false,
            },
          },
          recommendedAction: 'BLOCK IMMEDIATELY: Do not execute or navigate to client-side pseudo-schemes (javascript:, data:, file:).',
        };
      }

      return {
        url: rawUrl,
        normalizedUrl: norm.normalizedUrl,
        compositeScore: 0,
        severity: 'needs_review',
        confidence: 90,
        threatCategory: 'UNKNOWN',
        indicators: ['Malformed or unparseable URL input.'],
        detections: [{
          engine: 'URLValidator',
          category: 'invalid_format',
          severity: 'medium',
          ruleId: 'URL-ERR-001',
          title: 'Malformed URL Input',
          description: 'The provided target string cannot be parsed as a valid URL.',
        }],
        brandImpersonation: { detected: false },
        metadata: invalidMetadata,
        structural: emptyStructural,
        networkProbe: emptyProbe,
        evidence: {
          summary: 'The submitted string could not be parsed into a valid URL structure.',
          indicators: ['Malformed URL syntax'],
          riskFactors: [],
          safeFactors: ['No outbound network requests made.'],
          details: {
            metadata: invalidMetadata,
            brandImpersonation: { detected: false },
            structural: emptyStructural,
            networkProbe: emptyProbe,
            threatIntelMatched: false,
          },
        },
        recommendedAction: 'Verify URL syntax. Ensure protocol (http:// or https://) and registered domain are present.',
      };
    }

    const parsed = norm.parsed!;
    const hostname = norm.hostname;
    const domainParts = extractDomainParts(hostname);
    const isHttps = parsed.protocol === 'https:';
    const isShortener = KNOWN_SHORTENERS.has(hostname) || KNOWN_SHORTENERS.has(domainParts.baseDomain);

    // Dimension 8: IP Address Analysis
    const isIpAddress = norm.isIpAddress;
    const isObfuscatedIp = norm.isObfuscatedIp;

    // Userinfo check (e.g. https://google.com@attacker.com)
    const hasUserinfo = norm.hasUserinfo;

    // Construct metadata
    const metadata: UrlMetadata = {
      rawUrl,
      normalizedUrl: norm.normalizedUrl,
      protocol: parsed.protocol,
      isHttps,
      isDangerousScheme: false,
      hostname,
      domain: hostname,
      baseDomain: domainParts.baseDomain,
      subdomains: domainParts.subdomains,
      subdomainCount: domainParts.subdomains.length,
      tld: domainParts.tld,
      port: parsed.port || undefined,
      pathname: parsed.pathname,
      search: parsed.search,
      hash: parsed.hash,
      isIpAddress,
      ipAddress: isIpAddress ? hostname : undefined,
      normalizedIp: norm.normalizedIp,
      isObfuscatedIp,
      isShortener,
      shortenerService: isShortener ? hostname : undefined,
      isPunycode: norm.isPunycode,
      punycodeDecoded: norm.punycodeDecoded,
      isMixedScript: norm.isMixedScript,
      hasUserinfo,
      userinfoCredentials: norm.userinfoCredentials,
      isTopDomainWhitelist: norm.isTopDomainWhitelist,
    };

    // Dimension 14, 15: Subdomain Analysis & Depth
    const sld = domainParts.sld;
    const entropyScore = calculateShannonEntropy(sld);
    const hyphenCount = hostname.split('-').length - 1;
    const digitCount = (sld.match(/\d/g) || []).length;
    const digitRatio = sld.length > 0 ? Math.round((digitCount / sld.length) * 100) / 100 : 0;
    const isExcessiveSubdomains = domainParts.subdomains.length >= 3;

    // Dimension 19, 20, 21: Path Analysis (Credential, Payment, Login)
    const fullPath = parsed.pathname.toLowerCase();
    const credentialKeywordsFound: string[] = [];
    for (const kw of CREDENTIAL_PATH_KEYWORDS) {
      if (fullPath.includes(`/${kw}`) || fullPath.includes(`-${kw}`) || fullPath.includes(`_${kw}`)) {
        credentialKeywordsFound.push(kw);
      }
    }
    const hasCredentialPath = credentialKeywordsFound.length > 0;

    const paymentKeywordsFound: string[] = [];
    for (const kw of PAYMENT_PATH_KEYWORDS) {
      if (fullPath.includes(`/${kw}`) || fullPath.includes(`-${kw}`) || fullPath.includes(`_${kw}`)) {
        paymentKeywordsFound.push(kw);
      }
    }
    const hasPaymentPath = paymentKeywordsFound.length > 0;

    const loginKeywordsFound: string[] = [];
    for (const kw of LOGIN_PATH_KEYWORDS) {
      if (fullPath.includes(kw)) {
        loginKeywordsFound.push(kw);
      }
    }
    const hasLoginPath = loginKeywordsFound.length > 0;

    // Dimension 22: Download Behavior (Executable File Payload)
    const pathExtension = fullPath.split('.').pop()?.toLowerCase() || '';
    const hasExecutablePayload = EXECUTABLE_EXTENSIONS.has(pathExtension);

    // Dimension 23: Known Malicious Indicators (Path Traversal, Null Bytes)
    const hasPathTraversal = fullPath.includes('..') || fullPath.includes('%2e%2e') || fullPath.includes('%00');

    // Dimension 18: Query Parameters Analysis
    const openRedirectParamsFound: string[] = [];
    const sensitiveQueryParamsFound: string[] = [];
    let hasExternalRedirectTarget = false;
    let externalRedirectUrl = '';
    for (const [key, val] of parsed.searchParams.entries()) {
      const lowerKey = key.toLowerCase();
      if (OPEN_REDIRECT_PARAMS.has(lowerKey)) {
        openRedirectParamsFound.push(key);
        if (/^(?:https?:)?\/\//i.test(val.trim())) {
          hasExternalRedirectTarget = true;
          externalRedirectUrl = val.trim();
        }
      }
      if (SENSITIVE_QUERY_PARAMS.has(lowerKey)) {
        sensitiveQueryParamsFound.push(key);
      }
    }

    const structural: StructuralAnalysis = {
      entropyScore,
      hyphenCount,
      digitRatio,
      subdomainDepth: domainParts.subdomains.length,
      isExcessiveSubdomains,
      hasCredentialPath,
      credentialKeywordsFound,
      hasPaymentPath,
      paymentKeywordsFound,
      hasLoginPath,
      loginKeywordsFound,
      hasExecutablePayload,
      executableExtension: hasExecutablePayload ? pathExtension : undefined,
      hasOpenRedirectParam: openRedirectParamsFound.length > 0,
      openRedirectParamsFound,
      hasSensitiveQueryParams: sensitiveQueryParamsFound.length > 0,
      sensitiveQueryParamsFound,
      hasPathTraversal,
    };

    // Dimension 9, 10, 11, 12, 13: Brand Impersonation, Lookalikes, Typosquatting, Punycode
    const brandImpersonation: BrandImpersonationMatch = detectBrandImpersonation(hostname);

    // Top Domain Whitelist Immunity (Fast-Path Optimization)
    // If domain is on the trusted global authority whitelist, bypass expensive network calls
    if (norm.isTopDomainWhitelist) {
      safeFactors.push(`Domain '${domainParts.baseDomain}' is verified on the trusted global authority whitelist.`);
      safeFactors.push('Legitimate infrastructure: Structural keyword checks bypassed.');
      if (isHttps) safeFactors.push('Encrypted HTTPS transport active');

      const fastProbe: NetworkProbeResult = {
        probed: false,
        hasRedirects: false,
        redirectCount: 0,
        redirectChain: [norm.normalizedUrl],
        crossDomainRedirect: false,
        targetDomainChanged: false,
        ssrfSafe: true,
      };
      const fastDomainAge: DomainAgeInfo = { evaluated: true, domainAgeDays: 3650, isNewDomain: false };
      const fastTls: TlsInfo = { isHttps };
      const fastContent: ContentSignals = { evaluated: false };

      return {
        url: rawUrl,
        normalizedUrl: norm.normalizedUrl,
        compositeScore: 0,
        severity: 'safe',
        confidence: 95,
        threatCategory: 'SAFE',
        indicators: [],
        detections: [],
        brandImpersonation: { detected: false },
        metadata,
        structural,
        networkProbe: fastProbe,
        domainAge: fastDomainAge,
        tlsInfo: fastTls,
        contentSignals: fastContent,
        evidence: {
          summary: `URL belongs to verified top-tier legitimate organization (${domainParts.baseDomain}).`,
          indicators: [],
          riskFactors: [],
          safeFactors,
          details: {
            metadata,
            brandImpersonation: { detected: false },
            structural,
            networkProbe: fastProbe,
            domainAge: fastDomainAge,
            tlsInfo: fastTls,
            contentSignals: fastContent,
            threatIntelMatched: false,
          },
        },
        recommendedAction: 'Verified legitimate service. Standard browsing security applies.',
      };
    }

    // Optimization 1: Parallelize Independent Network & Threat Intelligence Probes
    const domainAgePromise: Promise<DomainAgeInfo> = (!options.skipDomainAge && !isIpAddress)
      ? domainAgeService.getDomainAgeInfo(domainParts.baseDomain).catch(() => ({ evaluated: false }))
      : Promise.resolve({ evaluated: false });

    const networkProbePromise: Promise<NetworkProbeResult> = options.skipNetworkProbe
      ? Promise.resolve({
          probed: false,
          hasRedirects: false,
          redirectCount: 0,
          redirectChain: [norm.normalizedUrl],
          crossDomainRedirect: false,
          targetDomainChanged: false,
          ssrfSafe: true,
        })
      : probeUrlSafely(norm.normalizedUrl).catch(() => ({
          probed: false,
          hasRedirects: false,
          redirectCount: 0,
          redirectChain: [norm.normalizedUrl],
          crossDomainRedirect: false,
          targetDomainChanged: false,
          ssrfSafe: true,
        }));

    const threatIntelPromise = threatIntel.checkDomain(hostname).catch(() => null);

    const [domainAge, networkProbe, threatIntelResult] = await Promise.all([
      domainAgePromise,
      networkProbePromise,
      threatIntelPromise,
    ]);

    const tlsInfo: TlsInfo = networkProbe.tlsInfo || { isHttps };
    const contentSignals: ContentSignals = networkProbe.contentSignals || { evaluated: false };

    // Dimension 24: Threat Intelligence Lookup
    let threatIntelMatched = false;
    let threatIntelProvider: string | undefined;
    if (threatIntelResult && threatIntelResult.detections && threatIntelResult.detections.length > 0) {
      threatIntelMatched = true;
      threatIntelProvider = threatIntelResult.provider;
      detections.push(...threatIntelResult.detections);
    }


    // SSRF Hazard Detection
    if (!networkProbe.ssrfSafe) {
      detections.push({
        engine: 'SSRFGuard',
        category: 'ssrf_hazard',
        severity: 'critical',
        ruleId: 'SSRF-001',
        title: 'Severe Security Risk: SSRF / Private Target Blocked',
        description: networkProbe.ssrfBlockedReason || 'URL resolves to forbidden private or loopback destination.',
        details: { resolvedIp: networkProbe.resolvedIp },
      });
      indicators.push(`Severe SSRF Hazard: Blocked access to private network (${networkProbe.resolvedIp || 'internal'})`);
      riskFactors.push('URL points to internal/private network addresses (SSRF hazard)');
    }

    // Executable Payload Delivery
    if (hasExecutablePayload) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'malware_delivery',
        severity: 'critical',
        ruleId: 'URL-PAYLOAD-001',
        title: `Direct Executable Payload Hosted: .${pathExtension}`,
        description: `URL directly points to an executable binary (.${pathExtension}), frequently used for drive-by malware delivery.`,
        details: { extension: pathExtension, path: fullPath },
      });
      indicators.push(`Executable Binary Download: Direct link to .${pathExtension} payload`);
      riskFactors.push(`Direct link to executable file (.${pathExtension}) poses immediate malware threat`);
    }

    // Brand Impersonation, Lookalike & Typosquatting
    if (brandImpersonation.detected) {
      const isCriticalImp =
        brandImpersonation.impersonationType === 'typosquatting' ||
        brandImpersonation.impersonationType === 'subdomain_spoof' ||
        brandImpersonation.impersonationType === 'homoglyph';
      const impSeverity = isCriticalImp ? 'critical' : 'high';

      detections.push({
        engine: 'BrandIntelligence',
        category: 'brand_impersonation',
        severity: impSeverity,
        ruleId: 'URL-BRD-IMP',
        title: `Brand Impersonation (${brandImpersonation.impersonationType}): ${brandImpersonation.targetedBrand}`,
        description: brandImpersonation.description || `Domain deceptively mimics ${brandImpersonation.targetedBrand}.`,
        details: {
          targetedBrand: brandImpersonation.targetedBrand,
          category: brandImpersonation.category,
          impersonationType: brandImpersonation.impersonationType,
          similarity: brandImpersonation.similarityScore,
          levenshteinDistance: brandImpersonation.levenshteinDistance,
        },
      });
      indicators.push(`Brand Impersonation (${brandImpersonation.impersonationType}): Targets '${brandImpersonation.targetedBrand}'`);
      riskFactors.push(`Unauthorized mimicry of recognized institution '${brandImpersonation.targetedBrand}'`);
    }

    // Mixed-Script Detection
    if (norm.isMixedScript) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'mixed_script',
        severity: 'high',
        ruleId: 'URL-UNICODE-001',
        title: `Deceptive Mixed-Script Domain (${norm.scriptsFound.join(' + ')})`,
        description: `Domain label blends Latin with ${norm.scriptsFound.filter((s) => s !== 'Latin').join(', ')} characters to visually spoof authentic domain names.`,
      });
      indicators.push(`Mixed-Script Homoglyph: Combines ${norm.scriptsFound.join(' and ')} characters`);
      riskFactors.push('Mixed Unicode scripts indicate deliberate visual spoofing technique');
    }

    // Direct IP Address Host
    if (isIpAddress) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'ip_hostname',
        severity: 'high',
        ruleId: 'URL-IP-001',
        title: isObfuscatedIp ? 'Obfuscated IP Address Hostname' : 'Raw Numeric IP Address Hostname',
        description: `URL points directly to an IP address (${hostname}) bypassing standard domain registration and reputation checks.`,
        details: { ip: hostname, obfuscated: isObfuscatedIp, normalizedIp: norm.normalizedIp },
      });
      indicators.push(`Direct IP Address Host: Points directly to numerical IP ${hostname}`);
      riskFactors.push('Direct numerical IP hosting common in malicious command-and-control servers');
    }

    // Userinfo @ Exploit
    if (hasUserinfo) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'userinfo_exploit',
        severity: 'critical',
        ruleId: 'URL-USR-001',
        title: 'Embedded Authentication Symbol (@) Redirection Trick',
        description: 'URL embeds userinfo credentials with @ to visually mislead users regarding the actual host.',
      });
      indicators.push("Embedded Userinfo: Deceptive '@' symbol hides true target hostname");
      riskFactors.push("URL uses '@' credential embedding trick to deceive users");
    }

    // High-Abuse TLD
    if (HIGH_RISK_TLDS.has(domainParts.tld)) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'suspicious_tld',
        severity: 'medium',
        ruleId: 'URL-TLD-001',
        title: `High-Abuse Top-Level Domain: .${domainParts.tld}`,
        description: `Domain uses .${domainParts.tld}, statistically associated with disproportionate scam and phishing campaigns.`,
      });
      indicators.push(`High-Abuse TLD: .${domainParts.tld} has elevated historical threat volume`);
      riskFactors.push(`Domain registered under high-abuse TLD .${domainParts.tld}`);
    } else {
      safeFactors.push(`TLD .${domainParts.tld || 'com'} has standard registrar reputation`);
    }

    // Excessive Subdomains Depth
    if (isExcessiveSubdomains) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'excessive_subdomains',
        severity: 'medium',
        ruleId: 'URL-SUB-001',
        title: `Excessive Subdomain Depth (${domainParts.subdomains.length} levels)`,
        description: `Hostname contains ${domainParts.subdomains.length} nested subdomain levels: [${domainParts.subdomains.join(', ')}].`,
      });
      indicators.push(`Excessive Subdomains: ${domainParts.subdomains.length} levels of subdomain nesting`);
      riskFactors.push('Deep subdomain nesting used to disguise registered root domain');
    }

    // High Shannon Entropy
    if (entropyScore >= 3.8 && sld.length >= 10) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'dga_anomaly',
        severity: 'medium',
        ruleId: 'URL-DGA-001',
        title: `High Shannon Entropy Domain Label (H=${entropyScore})`,
        description: `Domain label '${sld}' exhibits unusually high randomness characteristic of Domain Generation Algorithms (DGA).`,
      });
      indicators.push(`High Entropy: Domain label appears randomly generated (entropy: ${entropyScore})`);
      riskFactors.push('High randomness in domain name suggests automated DGA generation');
    }

    // Multi-Hyphenated Hostname
    if (hyphenCount >= 3) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'hyphenated_domain',
        severity: 'medium',
        ruleId: 'URL-HYP-001',
        title: `Multi-Hyphenated Domain Structure (${hyphenCount} hyphens)`,
        description: `Hostname contains ${hyphenCount} hyphens, commonly observed in fraudulent copycat registrations.`,
      });
      indicators.push(`Multi-Hyphenated Domain: ${hyphenCount} hyphens in hostname`);
      riskFactors.push('Excessive hyphens frequently used to combine brands with security buzzwords');
    }

    // Insecure Plain HTTP Transport
    if (!isHttps) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'transport_security',
        severity: 'medium',
        ruleId: 'URL-HTTP-001',
        title: 'Unencrypted Plain HTTP Transport',
        description: 'URL uses plaintext HTTP without TLS encryption. Credentials sent over this channel can be intercepted.',
      });
      indicators.push('Insecure Transport: Unencrypted plain HTTP protocol');
      riskFactors.push('Missing TLS encryption allows man-in-the-middle credential interception');
    } else {
      safeFactors.push('Encrypted HTTPS transport protocol active');
    }

    // URL Shortener
    if (isShortener) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'url_shortener',
        severity: 'low',
        ruleId: 'URL-SHORT-001',
        title: 'URL Shortener Service Detected',
        description: `URL uses known shortening service (${hostname}) to conceal the final destination.`,
      });
      indicators.push(`URL Shortener: ${hostname} conceals true destination`);
      riskFactors.push('Shortened URL masks final web landing page');
    }

    // Path Analysis: Credential, Payment, Login Paths
    if (hasCredentialPath) {
      const pathSeverity = brandImpersonation.detected || !isHttps ? 'high' : 'medium';
      detections.push({
        engine: 'URLIntelligence',
        category: 'credential_path',
        severity: pathSeverity,
        ruleId: 'URL-PATH-001',
        title: 'Credential / Authentication Action Path',
        description: `URL path contains sensitive account action keywords: [${credentialKeywordsFound.join(', ')}].`,
      });
      indicators.push(`Sensitive Account Path: Requests [${credentialKeywordsFound.join(', ')}] action`);
      riskFactors.push(`Path requests sensitive actions: ${credentialKeywordsFound.join(', ')}`);
    }

    if (hasPaymentPath && brandImpersonation.detected) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'payment_path',
        severity: 'high',
        ruleId: 'URL-PAY-001',
        title: 'Payment / Transaction Route on Impersonated Domain',
        description: `URL hosts payment pathways [${paymentKeywordsFound.join(', ')}] on unauthorized host.`,
      });
      indicators.push(`Payment Gateway Route: Soliciting transactions on unauthorized domain`);
      riskFactors.push('Financial transactions requested on non-authentic website');
    }

    // Query String: Open Redirect & Sensitive Tokens
    if (structural.hasOpenRedirectParam) {
      const isExternalTarget = hasExternalRedirectTarget;
      const redirSeverity = isExternalTarget ? 'high' : 'medium';
      detections.push({
        engine: 'URLIntelligence',
        category: 'open_redirect',
        severity: redirSeverity,
        ruleId: isExternalTarget ? 'URL-REDIR-EXPLOIT' : 'URL-REDIR-001',
        title: isExternalTarget
          ? `Open Redirect to External Destination: ${externalRedirectUrl}`
          : `Potential Open Redirect Query Parameter: ${openRedirectParamsFound.join(', ')}`,
        description: isExternalTarget
          ? `URL contains parameter '${openRedirectParamsFound.join(', ')}' actively diverting visitors to external target: ${externalRedirectUrl}.`
          : `URL specifies redirection targets in query string (${openRedirectParamsFound.join(', ')}).`,
      });
      indicators.push(
        isExternalTarget
          ? `Open Redirect: Parameter points to external target ${externalRedirectUrl}`
          : `Open Redirect Query: Contains redirect parameter '${openRedirectParamsFound.join(', ')}'`
      );
      riskFactors.push(`URL contains open redirect parameter '${openRedirectParamsFound.join(', ')}'`);
    }

    // Check if domain SLD has credential keyword (e.g. login-service.com, account-verify.com)
    const sldHasCredentialKeyword = CREDENTIAL_PATH_KEYWORDS.some((kw) => sld.includes(kw) && sld !== kw);
    if (sldHasCredentialKeyword && !norm.isTopDomainWhitelist) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'suspicious_sld_keyword',
        severity: 'medium',
        ruleId: 'URL-SLD-KEYWORD',
        title: `Credential Keyword in Domain Label: '${sld}'`,
        description: `Domain name contains sensitive security keywords, commonly used to masquerade as an authentic service portal.`,
      });
      indicators.push(`Deceptive Domain Keyword: '${sld}' contains authentication keywords`);
      riskFactors.push(`Domain label '${sld}' mimics an authentication portal`);
    }

    if (structural.hasSensitiveQueryParams) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'credential_query',
        severity: 'high',
        ruleId: 'URL-QRY-001',
        title: `Sensitive Credential Tokens in Query String: ${sensitiveQueryParamsFound.join(', ')}`,
        description: `URL transmits sensitive authentication parameters via unencoded GET query string: [${sensitiveQueryParamsFound.join(', ')}].`,
      });
      indicators.push(`Credential Query Params: Transmits [${sensitiveQueryParamsFound.join(', ')}] in URL query`);
      riskFactors.push('Sensitive authentication credentials exposed in GET query parameters');
    }

    // Network Probe Signals: Cross-Domain Redirects
    if (networkProbe.crossDomainRedirect) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'cross_domain_redirect',
        severity: 'high',
        ruleId: 'URL-NET-001',
        title: 'Cross-Domain Redirection to External Host',
        description: `URL automatically redirects from '${hostname}' to external domain: ${networkProbe.finalDestinationUrl}.`,
      });
      indicators.push(`Cross-Domain Redirection: Diverts traffic to ${networkProbe.finalDestinationUrl}`);
      riskFactors.push(`Redirects visitors off-domain to ${networkProbe.finalDestinationUrl}`);
    }

    // Dimension 4: Newly Registered Domain Signal
    if (domainAge && domainAge.evaluated && domainAge.isNewDomain) {
      detections.push({
        engine: 'DomainAgeInspector',
        category: 'newly_registered_domain',
        severity: 'medium',
        ruleId: 'URL-AGE-001',
        title: `Newly Registered Domain (${domainAge.domainAgeDays ?? '<30'} days old)`,
        description: `Domain was created very recently (${domainAge.creationDate || 'within 30 days'}). Statistically, newly registered domains have higher correlation with disposable phishing infrastructure.`,
        details: { domainAgeDays: domainAge.domainAgeDays, creationDate: domainAge.creationDate },
      });
      indicators.push(`Newly Registered Domain: Registered ${domainAge.domainAgeDays ?? '<30'} days ago`);
      riskFactors.push(`Domain is freshly registered (${domainAge.domainAgeDays ?? '<30'} days old)`);
    } else if (domainAge && domainAge.evaluated && typeof domainAge.domainAgeDays === 'number' && domainAge.domainAgeDays > 365) {
      safeFactors.push(`Established domain registration age (${Math.floor(domainAge.domainAgeDays / 365)} years)`);
    }

    // Dimension 25: Website Content Signals (Title Brand Mismatch & Password Forms)
    if (contentSignals && contentSignals.evaluated) {
      if (contentSignals.titleBrandMismatch) {
        detections.push({
          engine: 'WebContentInspector',
          category: 'title_impersonation',
          severity: 'critical',
          ruleId: 'URL-CONTENT-001',
          title: `Website Title Impersonates Brand: '${contentSignals.matchedBrandInTitle}'`,
          description: `The page title claims identity of '${contentSignals.matchedBrandInTitle}', but the hosting domain (${hostname}) is completely unauthorized.`,
          details: { pageTitle: contentSignals.pageTitle, matchedBrand: contentSignals.matchedBrandInTitle },
        });
        indicators.push(`Content Mimicry: Page title claims to be '${contentSignals.matchedBrandInTitle}'`);
        riskFactors.push(`Landing page masquerades as '${contentSignals.matchedBrandInTitle}'`);
      }

      if (contentSignals.hasPasswordInput && (brandImpersonation.detected || contentSignals.titleBrandMismatch)) {
        detections.push({
          engine: 'WebContentInspector',
          category: 'credential_harvesting_form',
          severity: 'critical',
          ruleId: 'URL-CONTENT-002',
          title: 'Active Password / Credential Harvesting Form',
          description: `Landing page contains password input fields while masquerading as a trusted brand.`,
        });
        indicators.push('Active Credential Harvester: Password input form found on deceptive host');
        riskFactors.push('Unverified page presents password submission form');
      }
    }

    // =========================================================================
    // Dimension 7: Anti-Unilateral Scoring & Composite Calculation
    // =========================================================================

    let baseScore = 0;
    let criticalRuleTriggered = false;

    // Hard Critical Overrides (permitting immediate critical classification)
    if (!networkProbe.ssrfSafe) {
      criticalRuleTriggered = true;
      baseScore = 95;
    } else if (hasExecutablePayload) {
      criticalRuleTriggered = true;
      baseScore = 90;
    } else if (threatIntelMatched) {
      criticalRuleTriggered = true;
      baseScore = 88;
    } else if (contentSignals.titleBrandMismatch && contentSignals.hasPasswordInput) {
      criticalRuleTriggered = true;
      baseScore = 95;
    }

    if (!criticalRuleTriggered) {
      let signalPoints = 0;
      let severeCount = 0;
      let moderateCount = 0;
      let minorCount = 0;

      for (const det of detections) {
        if (det.severity === 'critical') {
          signalPoints += 40;
          severeCount++;
        } else if (det.severity === 'high') {
          signalPoints += 25;
          severeCount++;
        } else if (det.severity === 'medium') {
          signalPoints += 15;
          moderateCount++;
        } else {
          signalPoints += 5;
          minorCount++;
        }
      }

      const totalSignals = severeCount + moderateCount + minorCount;

      // Anti-Unilateral Principle Guardrail:
      // A URL must NOT be classified as malicious solely because:
      // 1. It is newly registered
      // 2. It has plain HTTP
      // 3. It uses a high-abuse TLD
      // 4. It contains a single keyword
      // 5. It is a shortened URL
      if (totalSignals === 1 && severeCount === 0) {
        // Capped strictly at mild risk (<= 25)
        baseScore = Math.min(25, signalPoints);
      } else if (totalSignals === 1 && severeCount === 1) {
        // A single high signal without corroborating evidence caps at moderate (<= 45)
        baseScore = Math.min(45, signalPoints);
      } else if (totalSignals === 0) {
        baseScore = 0;
      } else {
        // Multi-signal consensus: Corroborated multi-vector threat escalation
        const brandWithCredOrTld =
          brandImpersonation.detected && (hasCredentialPath || hasPaymentPath || HIGH_RISK_TLDS.has(domainParts.tld));
        const correlationBonus = totalSignals >= 4
          ? 25
          : totalSignals >= 3
          ? 18
          : totalSignals >= 2
          ? (brandWithCredOrTld ? 20 : 10)
          : 0;
        baseScore = Math.min(99, Math.round(signalPoints + correlationBonus));
      }
    }

    const compositeScore = Math.min(100, Math.max(0, baseScore));

    // Determine Severity Tier & Category
    let severity: 'safe' | 'low' | 'medium' | 'high' | 'critical' | 'needs_review' = 'safe';
    let threatCategory = 'SAFE';

    if (criticalRuleTriggered || compositeScore >= 80) {
      severity = 'critical';
      threatCategory = !networkProbe.ssrfSafe
        ? 'SSRF_HAZARD'
        : hasExecutablePayload
        ? 'MALWARE'
        : 'PHISHING';
    } else if (compositeScore >= 60) {
      severity = 'high';
      threatCategory = brandImpersonation.detected ? 'IMPERSONATION' : 'PHISHING';
    } else if (compositeScore >= 40) {
      severity = 'medium';
      threatCategory = brandImpersonation.detected ? 'IMPERSONATION' : 'SUSPICIOUS_URL';
    } else if (compositeScore >= 20) {
      severity = 'low';
      threatCategory = 'LOW_RISK';
    } else {
      severity = 'safe';
      threatCategory = 'SAFE';
    }

    // Uncertainty Calibration for ambiguous isolated cases
    if (compositeScore >= 25 && compositeScore <= 45 && indicators.length === 1 && !brandImpersonation.detected) {
      severity = 'needs_review';
      threatCategory = 'needs_review';
    }

    // Confidence Calculation
    let confidence = 70;
    if (detections.length >= 3) confidence += 20;
    else if (detections.length >= 2) confidence += 15;
    if (networkProbe.probed) confidence += 5;
    if (domainAge && domainAge.evaluated) confidence += 5;
    if (criticalRuleTriggered) confidence = 98;
    confidence = Math.min(99, Math.max(50, confidence));

    // Contextual Recommendations
    let recommendedAction = '';
    if (severity === 'critical') {
      recommendedAction = 'CRITICAL SECURITY THREAT: Do not visit this URL or submit credentials. Target engages in active SSRF, drive-by malware delivery, or confirmed high-fidelity credential phishing.';
    } else if (severity === 'high') {
      recommendedAction = `HIGH RISK WARNING: Domain impersonates '${brandImpersonation.targetedBrand || 'trusted services'}' or uses deceptive domain formatting. Do not enter passwords or financial information.`;
    } else if (severity === 'medium') {
      recommendedAction = 'SUSPICIOUS URL: Multiple structural anomalies detected. Exercise caution and verify the authentic website domain through a known search engine before proceeding.';
    } else if (severity === 'needs_review') {
      recommendedAction = 'UNCERTAIN RESULT — NEEDS REVIEW: URL exhibits isolated ambiguous keywords or transport flags without definitive malicious proof. Inspect the domain carefully.';
    } else if (severity === 'low') {
      recommendedAction = 'NOTE: Minor irregularities detected (such as shortened link or high-abuse TLD). Exercise standard digital browsing vigilance.';
    } else {
      recommendedAction = 'URL appears standard and legitimate. Always ensure the browser padlock icon is present before submitting login credentials.';
    }

    const summary = indicators.length > 0
      ? `URL intelligence inspection flagged ${indicators.length} structural or security anomalies on ${hostname}.`
      : `URL structure and destination host (${hostname}) appear clean with no active SSRF or brand mimicry anomalies.`;

    const evidence: UrlThreatIndicators = {
      summary,
      indicators,
      riskFactors,
      safeFactors,
      details: {
        metadata,
        brandImpersonation,
        structural,
        networkProbe,
        domainAge,
        tlsInfo,
        contentSignals,
        threatIntelMatched,
        threatIntelProvider,
      },
    };

    return {
      url: rawUrl,
      normalizedUrl: norm.normalizedUrl,
      compositeScore,
      severity,
      confidence,
      threatCategory,
      indicators,
      detections,
      brandImpersonation,
      metadata,
      structural,
      networkProbe,
      domainAge,
      tlsInfo,
      contentSignals,
      evidence,
      recommendedAction,
    };
  }
}

export const urlIntelligence = new UrlIntelligence();
