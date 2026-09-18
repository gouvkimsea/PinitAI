import { describe, it, expect } from 'vitest';
import { urlIntelligence, calculateShannonEntropy, normalizeUrlString } from '../src/modules/url/urlIntelligence';
import { detectBrandImpersonation, calculateLevenshteinDistance, extractDomainParts } from '../src/modules/url/brandDetector';
import { urlNormalizer } from '../src/modules/url/urlNormalizer';
import { domainAgeService } from '../src/modules/url/domainAgeService';
import { contentAnalyzer } from '../src/modules/url/contentAnalyzer';

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

  // =========================================================================
  // Enhanced 25 Dimensions Coverage
  // =========================================================================

  describe('Dangerous Execution Pseudo-Schemes', () => {
    it('should immediately block javascript: pseudo-schemes with critical severity', async () => {
      const res = await urlIntelligence.analyze('javascript:alert(document.cookie)');

      expect(res.severity).toBe('critical');
      expect(res.compositeScore).toBeGreaterThanOrEqual(90);
      expect(res.threatCategory).toBe('MALWARE');
      expect(res.indicators.some((i) => i.includes('Dangerous execution pseudo-scheme'))).toBe(true);
    });

    it('should immediately block data: text/html pseudo-schemes with critical severity', async () => {
      const res = await urlIntelligence.analyze('data:text/html,<script>alert(1)</script>');

      expect(res.severity).toBe('critical');
      expect(res.compositeScore).toBeGreaterThanOrEqual(90);
    });
  });

  describe('Obfuscated IP Formats (Dword, Hex, Octal)', () => {
    it('should detect and normalize Dword integer IP address hosts', () => {
      const { isIp, isObfuscated, normalizedIp } = urlNormalizer.resolveObfuscatedIp('2130706433');
      expect(isIp).toBe(true);
      expect(isObfuscated).toBe(true);
      expect(normalizedIp).toBe('127.0.0.1');
    });

    it('should detect and normalize Hex IP address hosts', () => {
      const { isIp, isObfuscated, normalizedIp } = urlNormalizer.resolveObfuscatedIp('0x7f000001');
      expect(isIp).toBe(true);
      expect(isObfuscated).toBe(true);
      expect(normalizedIp).toBe('127.0.0.1');
    });

    it('should detect and normalize Dotted Octal IP address hosts', () => {
      const { isIp, isObfuscated, normalizedIp } = urlNormalizer.resolveObfuscatedIp('0177.0000.0000.0001');
      expect(isIp).toBe(true);
      expect(isObfuscated).toBe(true);
      expect(normalizedIp).toBe('127.0.0.1');
    });

    it('should flag obfuscated IP URLs during full intelligence scan', async () => {
      const res = await urlIntelligence.analyze('http://2130706433/login', { skipNetworkProbe: true });
      expect(res.metadata.isIpAddress).toBe(true);
      expect(res.metadata.isObfuscatedIp).toBe(true);
      expect(res.indicators.some((i) => i.includes('Direct IP Address Host'))).toBe(true);
    });
  });

  describe('Visual Lookalike Domains & Character Substitutions', () => {
    it('should detect visual lookalike substitution in paypaI.com (capital I)', () => {
      const match = detectBrandImpersonation('paypaI.com');
      expect(match.detected).toBe(true);
      expect(match.targetedBrand).toBe('PayPal');
    });

    it('should detect visual lookalike substitution in arnazon.com (rn for m)', () => {
      const match = detectBrandImpersonation('arnazon.com');
      expect(match.detected).toBe(true);
      expect(match.targetedBrand).toBe('Amazon');
    });

    it('should detect visual lookalike substitution in vvhatsapp.com (vv for w)', () => {
      const match = detectBrandImpersonation('vvhatsapp.com');
      expect(match.detected).toBe(true);
      expect(match.targetedBrand).toBe('WhatsApp');
    });
  });

  describe('Cambodian Institutions & Businesses Impersonation', () => {
    it('should detect fake ABA Bank combisquatting and credential harvesting', async () => {
      const res = await urlIntelligence.analyze('https://ababank-verify.com/login', { skipNetworkProbe: true });
      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.brandImpersonation.targetedBrand).toBe('ABA Bank');
      expect(res.compositeScore).toBeGreaterThanOrEqual(60);
      expect(['high', 'critical']).toContain(res.severity);
    });

    it('should detect fake Wing Bank combisquatting on high-risk TLD', async () => {
      const res = await urlIntelligence.analyze('https://wing-security-update.xyz/login', { skipNetworkProbe: true });
      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.brandImpersonation.targetedBrand).toBe('Wing Bank');
      expect(res.compositeScore).toBeGreaterThanOrEqual(60);
    });

    it('should detect fake ACLEDA Bank impersonation domain', async () => {
      const res = await urlIntelligence.analyze('https://acledabank-online.net/auth', { skipNetworkProbe: true });
      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.brandImpersonation.targetedBrand).toBe('ACLEDA Bank');
    });

    it('should detect fake Canadia Bank impersonation domain', async () => {
      const res = await urlIntelligence.analyze('https://canadiabank-verify.site/signin', { skipNetworkProbe: true });
      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.brandImpersonation.targetedBrand).toBe('Canadia Bank');
    });

    it('should detect fake General Department of Taxation (GDT) domain', async () => {
      const res = await urlIntelligence.analyze('https://taxgov-kh-portal.online/pay', { skipNetworkProbe: true });
      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.brandImpersonation.targetedBrand).toContain('Taxation');
    });

    it('should detect fake Cambodia Post parcel delivery scam domain', async () => {
      const res = await urlIntelligence.analyze('https://cambodiapost-fee-tracking.com/pay', { skipNetworkProbe: true });
      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.brandImpersonation.targetedBrand).toBe('Cambodia Post');
    });
  });

  describe('Fake Delivery & Shipping Scams', () => {
    it('should detect fake DHL Express package delivery phishing domain', async () => {
      const res = await urlIntelligence.analyze('https://dhl-parcel-delivery.xyz/tracking/redelivery', { skipNetworkProbe: true });
      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.brandImpersonation.targetedBrand).toBe('DHL Express');
      expect(res.compositeScore).toBeGreaterThanOrEqual(60);
    });

    it('should detect fake FedEx package fee scam domain', async () => {
      const res = await urlIntelligence.analyze('https://fedex-package-update.online/pay-fee', { skipNetworkProbe: true });
      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.brandImpersonation.targetedBrand).toBe('FedEx');
    });
  });

  describe('Website Content Signals (Title Brand Mismatch & Form Detection)', () => {
    it('should flag title brand mismatch when page claims to be a brand on unauthorized host', () => {
      const html = '<html><head><title>ABA Bank - Mobile Banking Login</title></head><body>Welcome</body></html>';
      const signals = contentAnalyzer.analyze(html, 'evil-phishing-host.xyz');

      expect(signals.evaluated).toBe(true);
      expect(signals.titleBrandMismatch).toBe(true);
      expect(signals.matchedBrandInTitle).toBe('ABA Bank');
    });

    it('should detect active password input form in HTML snippet', () => {
      const html = '<form action="/steal"><input type="text" name="user"><input type="password" name="pass"></form>';
      const signals = contentAnalyzer.analyze(html, 'fake-login.com');

      expect(signals.hasPasswordInput).toBe(true);
      expect(signals.hasLoginForm).toBe(true);
      expect(signals.isSuspiciousLoginDrop).toBe(true);
    });

    it('should NOT flag title brand mismatch on legitimate brand domain', () => {
      const html = '<html><head><title>ABA Bank - Personal Banking</title></head></html>';
      const signals = contentAnalyzer.analyze(html, 'ababank.com');

      expect(signals.titleBrandMismatch).toBe(false);
    });
  });

  describe('Top Domain Whitelist Immunity (False Positive Prevention)', () => {
    it('should assign score 0 (SAFE) to legitimate Google search query', async () => {
      const res = await urlIntelligence.analyze('https://www.google.com/search?q=cybersecurity+training');
      expect(res.compositeScore).toBe(0);
      expect(res.severity).toBe('safe');
      expect(res.metadata.isTopDomainWhitelist).toBe(true);
    });

    it('should assign score 0 (SAFE) to GitHub login path', async () => {
      const res = await urlIntelligence.analyze('https://github.com/login');
      expect(res.compositeScore).toBe(0);
      expect(res.severity).toBe('safe');
      expect(res.metadata.isTopDomainWhitelist).toBe(true);
    });

    it('should assign score 0 (SAFE) to Microsoft download portal', async () => {
      const res = await urlIntelligence.analyze('https://www.microsoft.com/en-us/software-download/windows11');
      expect(res.compositeScore).toBe(0);
      expect(res.severity).toBe('safe');
      expect(res.metadata.isTopDomainWhitelist).toBe(true);
    });

    it('should assign score 0 (SAFE) to authentic ABA Bank portal', async () => {
      const res = await urlIntelligence.analyze('https://www.ababank.com/personal-banking/');
      expect(res.compositeScore).toBe(0);
      expect(res.severity).toBe('safe');
      expect(res.metadata.isTopDomainWhitelist).toBe(true);
    });
  });

  describe('Domain Age & Anti-Unilateral Principle', () => {
    it('should NOT declare a newly registered domain malicious solely due to age', async () => {
      domainAgeService.setMockDomainAge('brand-new-site.com', 5, 'GoDaddy');
      const res = await urlIntelligence.analyze('https://brand-new-site.com/about-us', { skipNetworkProbe: true });

      // Anti-unilateral rule: newly registered domain alone cannot trigger high or critical risk
      expect(res.domainAge?.isNewDomain).toBe(true);
      expect(res.compositeScore).toBeLessThanOrEqual(30);
      expect(res.severity).not.toBe('critical');
      expect(res.severity).not.toBe('high');
    });

    it('should escalate to high risk when newly registered domain combines with brand impersonation', async () => {
      domainAgeService.setMockDomainAge('paypal-instant-verify.com', 3, 'Namecheap');
      const res = await urlIntelligence.analyze('https://paypal-instant-verify.com/login', { skipNetworkProbe: true });

      expect(res.domainAge?.isNewDomain).toBe(true);
      expect(res.brandImpersonation.detected).toBe(true);
      expect(res.compositeScore).toBeGreaterThanOrEqual(60);
      expect(['high', 'critical']).toContain(res.severity);
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
