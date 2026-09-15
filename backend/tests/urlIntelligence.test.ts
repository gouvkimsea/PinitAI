import { describe, it, expect } from 'vitest';
import { urlIntelligence, calculateShannonEntropy, normalizeUrlString } from '../src/modules/url/urlIntelligence';
import { detectBrandImpersonation, calculateLevenshteinDistance, extractDomainParts } from '../src/modules/url/brandDetector';

describe('Dedicated URL Intelligence Module', () => {
  describe('URL Normalization & Component Parsing', () => {
    it('should correctly normalize protocols, ports, and trailing slashes', () => {
      expect(normalizeUrlString('example.com')).toBe('https://example.com');
      expect(normalizeUrlString('HTTP://EXAMPLE.COM:80/')).toBe('http://example.com');
      expect(normalizeUrlString('https://example.com:443/path/')).toBe('https://example.com/path/');
    });

    it('should correctly extract compound ccTLDs (.co.uk, .com.kh)', () => {
      const ukParts = extractDomainParts('secure.login.paypal.co.uk');
      expect(ukParts.baseDomain).toBe('paypal.co.uk');
      expect(ukParts.sld).toBe('paypal');
      expect(ukParts.subdomain).toBe('secure.login');
      expect(ukParts.subdomains).toEqual(['secure', 'login']);

      const khParts = extractDomainParts('banking.ababank.com.kh');
      expect(khParts.baseDomain).toBe('ababank.com.kh');
      expect(khParts.sld).toBe('ababank');
    });

    it('should calculate Shannon entropy for domain labels', () => {
      const normalEntropy = calculateShannonEntropy('google');
      const randomDgaEntropy = calculateShannonEntropy('x8f29z11ba9q');
      expect(randomDgaEntropy).toBeGreaterThan(normalEntropy);
      expect(randomDgaEntropy).toBeGreaterThan(3.2);
    });
  });

  describe('Brand Impersonation & Typosquatting', () => {
    it('should calculate Levenshtein distance accurately', () => {
      expect(calculateLevenshteinDistance('paypal', 'paypa1')).toBe(1);
      expect(calculateLevenshteinDistance('paypal', 'paypai')).toBe(1);
      expect(calculateLevenshteinDistance('paypal', 'paypaal')).toBe(1);
      expect(calculateLevenshteinDistance('amazon', 'arnazon')).toBe(2);
      expect(calculateLevenshteinDistance('apple', 'apple')).toBe(0);
    });

    it('should detect typosquatting against PayPal (d=1)', () => {
      const match1 = detectBrandImpersonation('paypa1.com');
      expect(match1.detected).toBe(true);
      expect(match1.targetedBrand).toBe('PayPal');
      expect(match1.impersonationType).toBe('typosquatting');
      expect(match1.levenshteinDistance).toBe(1);

      const match2 = detectBrandImpersonation('paypai.com');
      expect(match2.detected).toBe(true);
      expect(match2.targetedBrand).toBe('PayPal');
    });

    it('should detect combisquatting with deceptive keywords', () => {
      const match = detectBrandImpersonation('paypal-security-verification.com');
      expect(match.detected).toBe(true);
      expect(match.targetedBrand).toBe('PayPal');
      expect(match.impersonationType).toBe('combisquatting');
    });

    it('should detect subdomain injection of brand into unrelated domain', () => {
      const match = detectBrandImpersonation('paypal.com.verify-account.attacker.xyz');
      expect(match.detected).toBe(true);
      expect(match.targetedBrand).toBe('PayPal');
      expect(match.impersonationType).toBe('subdomain_spoof');
    });

    it('should NOT flag legitimate brand domains as impersonation', () => {
      const legitCom = detectBrandImpersonation('paypal.com');
      expect(legitCom.detected).toBe(false);

      const legitUk = detectBrandImpersonation('paypal.co.uk');
      expect(legitUk.detected).toBe(false);

      const legitApple = detectBrandImpersonation('apple.com');
      expect(legitApple.detected).toBe(false);

      const legitAba = detectBrandImpersonation('ababank.com');
      expect(legitAba.detected).toBe(false);
    });
  });

  describe('12 URL Intelligence Dimensions', () => {
    it('1. Suspicious domains: High-risk TLD, hyphens, entropy', async () => {
      const res = await urlIntelligence.analyze('https://secure-login-account-verify.xyz', { skipNetworkProbe: true });

      expect(res.metadata.tld).toBe('xyz');
      expect(res.structural.hyphenCount).toBeGreaterThanOrEqual(3);
      expect(res.indicators.some((i) => i.includes('High-Abuse TLD') || i.includes('Multi-Hyphenated'))).toBe(true);
    });

    it('2. Look-alike / Punycode Homoglyph domains', async () => {
      const res = await urlIntelligence.analyze('https://xn--pypal-4ve.com', { skipNetworkProbe: true });

      expect(res.metadata.isPunycode).toBe(true);
      expect(res.brandImpersonation.impersonationType).toBe('homoglyph');
    });

    it('3. Typosquatting: Detected with edit distance', async () => {
      const res = await urlIntelligence.analyze('https://paypa1.com/signin', { skipNetworkProbe: true });

      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.brandImpersonation.impersonationType).toBe('typosquatting');
      expect(res.brandImpersonation.levenshteinDistance).toBe(1);
    });

    it('4. Raw Numeric IP address URLs', async () => {
      const res = await urlIntelligence.analyze('http://45.33.32.156/portal/login', { skipNetworkProbe: true });

      expect(res.metadata.isIpAddress).toBe(true);
      expect(res.indicators.some((i) => i.includes('Direct IP Address Host'))).toBe(true);
    });

    it('5. URL shorteners: Masked destination detection', async () => {
      const res = await urlIntelligence.analyze('https://bit.ly/3xYqz1', { skipNetworkProbe: true });

      expect(res.metadata.isShortener).toBe(true);
      expect(res.indicators.some((i) => i.includes('URL Shortener'))).toBe(true);
    });

    it('6. Excessive subdomains depth', async () => {
      const res = await urlIntelligence.analyze('https://login.secure.verify.portal.chase.attacker.com', { skipNetworkProbe: true });

      expect(res.structural.isExcessiveSubdomains).toBe(true);
      expect(res.structural.subdomainDepth).toBeGreaterThanOrEqual(3);
    });

    it('7. Suspicious paths: Executable payload download (.exe)', async () => {
      const res = await urlIntelligence.analyze('https://fileshare-portal.com/invoices/payment_slip.exe', { skipNetworkProbe: true });

      expect(res.structural.hasExecutablePayload).toBe(true);
      expect(res.structural.executableExtension).toBe('exe');
      expect(res.severity).toBe('critical');
      expect(res.threatCategory).toBe('MALWARE');
    });

    it('8. Suspicious query parameters: Open redirect parameters', async () => {
      const res = await urlIntelligence.analyze('https://login-service.com?redirect=https://evil-phishing.com/steal', { skipNetworkProbe: true });

      expect(res.structural.hasOpenRedirectParam).toBe(true);
      expect(res.structural.openRedirectParamsFound).toContain('redirect');
    });

    it('9. HTTPS status: Flag unencrypted plain HTTP', async () => {
      const res = await urlIntelligence.analyze('http://login-portal.com', { skipNetworkProbe: true });

      expect(res.metadata.isHttps).toBe(false);
      expect(res.indicators.some((i) => i.includes('Insecure Transport'))).toBe(true);
    });

    it('10. Userinfo credentials @ redirection trick', async () => {
      const res = await urlIntelligence.analyze('https://google.com@evil-attacker.com/login', { skipNetworkProbe: true });

      expect(res.metadata.hasUserinfo).toBe(true);
      expect(res.indicators.some((i) => i.includes('Embedded Userinfo'))).toBe(true);
    });

    it('11. SSRF Protection: Immediate block of cloud metadata IP (169.254.169.254)', async () => {
      const res = await urlIntelligence.analyze('http://169.254.169.254/latest/meta-data/');

      expect(res.networkProbe.ssrfSafe).toBe(false);
      expect(res.severity).toBe('critical');
      expect(res.compositeScore).toBeGreaterThanOrEqual(85);
      expect(res.threatCategory).toBe('SSRF_HAZARD');
    });

    it('12. SSRF Protection: Immediate block of private IPv4 (192.168.1.1)', async () => {
      const res = await urlIntelligence.analyze('http://192.168.1.1/admin');

      expect(res.networkProbe.ssrfSafe).toBe(false);
      expect(res.severity).toBe('critical');
    });
  });

  describe('Anti-Unilateral Rule Enforcement', () => {
    it('should NOT declare a URL malicious solely based on unencrypted HTTP', async () => {
      // Normal personal blog on plain HTTP with no other malicious factors
      const res = await urlIntelligence.analyze('http://johndoe-travelblog.com', { skipNetworkProbe: true });

      // Anti-unilateral rule prevents a single minor signal from triggering High or Critical
      expect(res.compositeScore).toBeLessThanOrEqual(30);
      expect(res.severity).not.toBe('critical');
      expect(res.severity).not.toBe('high');
    });

    it('should NOT declare a URL malicious solely based on a shortened link', async () => {
      const res = await urlIntelligence.analyze('https://tinyurl.com/meeting-notes', { skipNetworkProbe: true });

      expect(res.compositeScore).toBeLessThanOrEqual(30);
      expect(res.severity).not.toBe('critical');
      expect(res.severity).not.toBe('high');
    });

    it('should escalate composite score when multiple corroborating threats align', async () => {
      // Typosquatting + plain HTTP + high-risk TLD + credential login path
      const res = await urlIntelligence.analyze('http://paypa1-account-update.xyz/login', { skipNetworkProbe: true });

      expect(res.compositeScore).toBeGreaterThanOrEqual(60);
      expect(['high', 'critical']).toContain(res.severity);
      expect(res.brandImpersonation.detected).toBe(true);
    });
  });

  describe('Structured Evidence Contract', () => {
    it('should return complete structured evidence and actionable advice', async () => {
      const res = await urlIntelligence.analyze('https://paypal-security-verification.com/login', { skipNetworkProbe: true });

      expect(res).toHaveProperty('url');
      expect(res).toHaveProperty('normalizedUrl');
      expect(res).toHaveProperty('compositeScore');
      expect(res).toHaveProperty('severity');
      expect(res).toHaveProperty('confidence');
      expect(res).toHaveProperty('threatCategory');
      expect(res).toHaveProperty('indicators');
      expect(res).toHaveProperty('detections');
      expect(res).toHaveProperty('brandImpersonation');
      expect(res).toHaveProperty('metadata');
      expect(res).toHaveProperty('structural');
      expect(res).toHaveProperty('networkProbe');
      expect(res).toHaveProperty('evidence');
      expect(res).toHaveProperty('recommendedAction');

      expect(res.evidence.details.metadata.domain).toBe('paypal-security-verification.com');
      expect(typeof res.recommendedAction).toBe('string');
      expect(res.recommendedAction.length).toBeGreaterThan(15);
    });
  });
});
