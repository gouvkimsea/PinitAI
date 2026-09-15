import { describe, it, expect } from 'vitest';
import { normalizeUrl, analyzeUrl } from '../src/scanners/url/urlScanner';

describe('URL Security Scanner', () => {
  it('should normalize URLs properly', () => {
    expect(normalizeUrl('example.com')).toBe('https://example.com');
    expect(normalizeUrl('HTTP://EXAMPLE.COM:80/')).toBe('http://example.com');
    expect(normalizeUrl('https://example.com:443/test/')).toBe('https://example.com/test/');
  });

  it('should detect brand impersonation in subdomains', async () => {
    const fakeUrl = 'https://paypal.com.verify-user-account.suspicious-domain.xyz/login';
    const result = await analyzeUrl(fakeUrl);

    expect(result.detections.some((d) => d.category === 'brand_impersonation')).toBe(true);
    expect(result.detections.some((d) => d.category === 'suspicious_tld')).toBe(true);
  });

  it('should flag unencrypted plain HTTP protocol', async () => {
    const httpUrl = 'http://insecure-login-portal.com';
    const result = await analyzeUrl(httpUrl);

    expect(result.metadata.isHttps).toBe(false);
    expect(result.detections.some((d) => d.category === 'transport_security')).toBe(true);
  });

  it('should not flag legitimate brand domains on compound ccTLDs (e.g. .co.uk)', async () => {
    const legitimateUrl = 'https://paypal.co.uk/signin';
    const result = await analyzeUrl(legitimateUrl);

    expect(result.detections.some((d) => d.category === 'brand_impersonation')).toBe(false);
  });

  it('should block SSRF URLs immediately', async () => {
    const ssrfUrl = 'http://169.254.169.254/latest/meta-data/';
    const result = await analyzeUrl(ssrfUrl);

    expect(result.detections.some((d) => d.category === 'ssrf_hazard')).toBe(true);
    expect(result.detections[0].severity).toBe('critical');
  });
});
