import { threatIntel } from '../../scanners/threatIntel/threatIntelProvider';
import { DetectionItem } from '../../types';
import { detectBrandImpersonation, extractDomainParts } from './brandDetector';
import { probeUrlSafely } from './networkProbe';
import {
  BrandImpersonationMatch,
  NetworkProbeResult,
  StructuralAnalysis,
  UrlIntelligenceResult,
  UrlMetadata,
  UrlThreatIndicators,
} from './types';

const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'work', 'click',
  'country', 'stream', 'download', 'racing', 'win', 'vip', 'cam', 'quest',
  'loan', 'cfd', 'zip', 'mov', 'surf', 'icu', 'fit'
]);

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'cutt.ly', 'rb.gy', 'shorturl.at', 'rebrand.ly', 'tiny.cc', 'clck.ru', 'v.gd'
]);

const CREDENTIAL_PATH_KEYWORDS = [
  'login', 'signin', 'account', 'verify', 'verification', 'security',
  'banking', 'update', 'wallet', 'claim', 'auth', 'authenticate',
  'password', 'reset', 'portal', 'confirm', 'identity', 'unlock'
];

const EXECUTABLE_EXTENSIONS = new Set([
  'exe', 'apk', 'scr', 'bat', 'cmd', 'vbs', 'pif', 'jar', 'msi', 'ps1', 'iso', 'hta'
]);

const OPEN_REDIRECT_PARAMS = new Set([
  'redirect', 'redirect_to', 'redirect_uri', 'return', 'return_to',
  'url', 'target', 'dest', 'destination', 'next', 'r', 'goto', 'link'
]);

const SENSITIVE_QUERY_PARAMS = new Set([
  'password', 'pwd', 'pass', 'token', 'otp', 'pin', 'ssn', 'credit_card', 'secret'
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

/**
 * Normalizes a URL for consistent parsing, canonicalization, and deduplication.
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

export class UrlIntelligence {
  /**
   * Performs an exhaustive multi-dimensional intelligence scan on a URL.
   */
  async analyze(rawUrl: string, options: { skipNetworkProbe?: boolean } = {}): Promise<UrlIntelligenceResult> {
    const normalizedUrl = normalizeUrlString(rawUrl);
    const detections: DetectionItem[] = [];
    const indicators: string[] = [];
    const riskFactors: string[] = [];
    const safeFactors: string[] = [];

    // 1. Parsing & Validation
    let parsed: URL;
    try {
      parsed = new URL(normalizedUrl);
    } catch {
      const invalidMetadata: UrlMetadata = {
        rawUrl,
        normalizedUrl,
        protocol: '',
        isHttps: false,
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
        ssrfSafe: false,
      };

      return {
        url: rawUrl,
        normalizedUrl,
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

    const hostname = parsed.hostname.toLowerCase();
    const domainParts = extractDomainParts(hostname);
    const isHttps = parsed.protocol === 'https:';
    const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
    const isShortener = KNOWN_SHORTENERS.has(hostname) || KNOWN_SHORTENERS.has(domainParts.baseDomain);

    // IP address checks (IPv4, IPv6, obfuscated)
    const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    const isIpv6 = /^\[?[a-f0-9:]+\]?$/i.test(hostname) && hostname.includes(':');
    const isObfuscatedIp = /^0x[0-9a-f]+$/i.test(hostname) || /^\d{8,10}$/.test(hostname) || /^0[0-7]+(\.[0-7]+){3}$/.test(hostname);
    const isIpAddress = isIpv4 || isIpv6 || isObfuscatedIp;

    // Userinfo check (e.g. https://google.com@attacker.com)
    const hasUserinfo = Boolean(parsed.username || parsed.password);

    // Construct metadata
    const metadata: UrlMetadata = {
      rawUrl,
      normalizedUrl,
      protocol: parsed.protocol,
      isHttps,
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
      isObfuscatedIp,
      isShortener,
      shortenerService: isShortener ? hostname : undefined,
      isPunycode,
      hasUserinfo,
      userinfoCredentials: hasUserinfo ? `${parsed.username}:${parsed.password}` : undefined,
    };

    // 2. Structural & Query Analysis
    const sld = domainParts.sld;
    const entropyScore = calculateShannonEntropy(sld);
    const hyphenCount = hostname.split('-').length - 1;
    const digitCount = (sld.match(/\d/g) || []).length;
    const digitRatio = sld.length > 0 ? Math.round((digitCount / sld.length) * 100) / 100 : 0;
    const isExcessiveSubdomains = domainParts.subdomains.length >= 3;

    // Path analysis
    const fullPath = parsed.pathname.toLowerCase();
    const credentialKeywordsFound: string[] = [];
    for (const kw of CREDENTIAL_PATH_KEYWORDS) {
      if (fullPath.includes(`/${kw}`) || fullPath.includes(`-${kw}`) || fullPath.includes(`_${kw}`)) {
        credentialKeywordsFound.push(kw);
      }
    }
    const hasCredentialPath = credentialKeywordsFound.length > 0;

    // Executable file payload
    const pathExtension = fullPath.split('.').pop()?.toLowerCase() || '';
    const hasExecutablePayload = EXECUTABLE_EXTENSIONS.has(pathExtension);
    const hasPathTraversal = fullPath.includes('..') || fullPath.includes('%2e%2e');

    // Query parameters analysis
    const openRedirectParamsFound: string[] = [];
    const sensitiveQueryParamsFound: string[] = [];
    for (const [key] of parsed.searchParams.entries()) {
      const lowerKey = key.toLowerCase();
      if (OPEN_REDIRECT_PARAMS.has(lowerKey)) {
        openRedirectParamsFound.push(key);
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
      hasExecutablePayload,
      executableExtension: hasExecutablePayload ? pathExtension : undefined,
      hasOpenRedirectParam: openRedirectParamsFound.length > 0,
      openRedirectParamsFound,
      hasSensitiveQueryParams: sensitiveQueryParamsFound.length > 0,
      sensitiveQueryParamsFound,
      hasPathTraversal,
    };

    // 3. Brand Impersonation & Typosquatting Analysis
    const brandImpersonation: BrandImpersonationMatch = detectBrandImpersonation(hostname);

    // 4. Safe Network Probing & Hop-by-Hop Redirect Tracking
    let networkProbe: NetworkProbeResult;
    if (options.skipNetworkProbe) {
      networkProbe = {
        probed: false,
        hasRedirects: false,
        redirectCount: 0,
        redirectChain: [normalizedUrl],
        crossDomainRedirect: false,
        targetDomainChanged: false,
        ssrfSafe: true,
      };
    } else {
      networkProbe = await probeUrlSafely(normalizedUrl);
    }

    // 5. Threat Intelligence Lookup
    let threatIntelMatched = false;
    let threatIntelProvider: string | undefined;
    try {
      const intel = await threatIntel.checkDomain(hostname);
      if (intel && intel.detections && intel.detections.length > 0) {
        threatIntelMatched = true;
        threatIntelProvider = intel.provider;
        detections.push(...intel.detections);
      }
    } catch {
      // Non-blocking fallback
    }

    // 6. Signal Accumulation & Granular Heuristics

    // Check SSRF
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

    // Check Brand Impersonation
    if (brandImpersonation.detected) {
      const impSeverity = brandImpersonation.impersonationType === 'typosquatting' || brandImpersonation.impersonationType === 'subdomain_spoof' ? 'critical' : 'high';
      detections.push({
        engine: 'BrandIntelligence',
        category: 'brand_impersonation',
        severity: impSeverity,
        ruleId: 'URL-BRD-IMP',
        title: `Brand Impersonation (${brandImpersonation.impersonationType}): ${brandImpersonation.targetedBrand}`,
        description: brandImpersonation.description || `Domain deceptively mimics ${brandImpersonation.targetedBrand}.`,
        details: {
          targetedBrand: brandImpersonation.targetedBrand,
          impersonationType: brandImpersonation.impersonationType,
          similarity: brandImpersonation.similarityScore,
          levenshteinDistance: brandImpersonation.levenshteinDistance,
        },
      });
      indicators.push(`Brand Impersonation (${brandImpersonation.impersonationType}): Targets '${brandImpersonation.targetedBrand}'`);
      riskFactors.push(`Unauthorized mimicry of recognized brand '${brandImpersonation.targetedBrand}'`);
    }

    // Check Raw IP URL
    if (isIpAddress) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'ip_hostname',
        severity: 'high',
        ruleId: 'URL-IP-001',
        title: isObfuscatedIp ? 'Obfuscated IP Address Hostname' : 'Raw Numeric IP Address Hostname',
        description: `URL points directly to an IP address (${hostname}) bypassing standard domain registration and reputation checks.`,
        details: { ip: hostname, obfuscated: isObfuscatedIp },
      });
      indicators.push(`Direct IP Address Host: Points directly to numerical IP ${hostname}`);
      riskFactors.push('Direct numerical IP hosting common in malicious command-and-control servers');
    }

    // Check Userinfo @ Exploit
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

    // Check Executable Download
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

    // Check High-Risk TLD
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

    // Check Excessive Subdomains
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

    // Check High Entropy / DGA
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

    // Check Excessive Hyphens
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

    // Check Insecure Plain HTTP
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

    // Check URL Shortener
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

    // Check Suspicious Credential Path
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

    // Check Open Redirect / Suspicious Query
    if (structural.hasOpenRedirectParam) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'open_redirect',
        severity: 'medium',
        ruleId: 'URL-REDIR-001',
        title: `Potential Open Redirect Query Parameter: ${openRedirectParamsFound.join(', ')}`,
        description: `URL specifies redirection targets in query string (${openRedirectParamsFound.join(', ')}).`,
      });
      indicators.push(`Open Redirect Query: Contains redirect parameter '${openRedirectParamsFound.join(', ')}'`);
      riskFactors.push(`URL contains open redirect parameter '${openRedirectParamsFound.join(', ')}'`);
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

    // Check Network Redirect Anomalies
    if (networkProbe.crossDomainRedirect) {
      detections.push({
        engine: 'URLIntelligence',
        category: 'cross_domain_redirect',
        severity: 'high',
        ruleId: 'URL-NET-001',
        title: 'Cross-Domain Redirection to Unrelated Host',
        description: `URL automatically redirects from '${hostname}' to external domain: ${networkProbe.finalDestinationUrl}.`,
      });
      indicators.push(`Cross-Domain Redirection: Diverts traffic to ${networkProbe.finalDestinationUrl}`);
      riskFactors.push(`Redirects visitors off-domain to ${networkProbe.finalDestinationUrl}`);
    }

    // 7. Multi-Signal Scoring & Anti-Unilateral Rule Enforcement
    let baseScore = 0;
    let criticalRuleTriggered = false;

    // Critical Security Rules (Permitted Unilateral Overrides)
    if (!networkProbe.ssrfSafe) {
      criticalRuleTriggered = true;
      baseScore = 95;
    } else if (hasExecutablePayload) {
      criticalRuleTriggered = true;
      baseScore = 90;
    } else if (threatIntelMatched) {
      criticalRuleTriggered = true;
      baseScore = 88;
    }

    if (!criticalRuleTriggered) {
      // Accumulate weighted scores across independent signals
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

      // Anti-Unilateral Principle:
      // If only 1 moderate or minor signal triggered (e.g. only plain HTTP, or only .xyz TLD, or only a shortener),
      // it CANNOT unilaterally push the result into High or Critical risk.
      if (totalSignals === 1 && severeCount === 0) {
        // Capped strictly at mild risk
        baseScore = Math.min(25, signalPoints);
      } else if (totalSignals === 1 && severeCount === 1) {
        // A single high signal without corroborating factors caps at moderate risk (max 45)
        baseScore = Math.min(45, signalPoints);
      } else {
        // Multi-signal consensus: compute composite score with correlation amplification
        const correlationBonus = totalSignals >= 3 ? 15 : totalSignals >= 2 ? 8 : 0;
        baseScore = Math.min(99, Math.round(signalPoints * 0.85 + correlationBonus));
      }
    }

    const compositeScore = Math.min(100, Math.max(0, baseScore));

    // Determine Severity Tier & Category
    let severity: 'safe' | 'low' | 'medium' | 'high' | 'critical' | 'needs_review' = 'safe';
    let threatCategory = 'SAFE';

    if (criticalRuleTriggered || compositeScore >= 80) {
      severity = 'critical';
      threatCategory = !networkProbe.ssrfSafe ? 'SSRF_HAZARD' : hasExecutablePayload ? 'MALWARE' : 'PHISHING';
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

    // Support uncertain borderline cases
    if (compositeScore >= 25 && compositeScore <= 45 && indicators.length === 1 && !brandImpersonation.detected) {
      severity = 'needs_review';
      threatCategory = 'needs_review';
    }

    // Confidence calculation
    let confidence = 70;
    if (detections.length >= 3) confidence += 20;
    else if (detections.length >= 2) confidence += 15;
    if (networkProbe.probed) confidence += 5;
    if (criticalRuleTriggered) confidence = 98;
    confidence = Math.min(99, Math.max(50, confidence));

    // Formulate Contextual Recommendations
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
        threatIntelMatched,
        threatIntelProvider,
      },
    };

    return {
      url: rawUrl,
      normalizedUrl,
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
      evidence,
      recommendedAction,
    };
  }
}

export const urlIntelligence = new UrlIntelligence();
