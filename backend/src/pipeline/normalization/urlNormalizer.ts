export interface NormalizedUrlResult {
  rawUrl: string;
  normalizedUrl: string;
  protocol: 'http:' | 'https:';
  hostname: string;
  domain: string;
  subdomain?: string;
  tld: string;
  port?: string;
  pathname: string;
  hasTrackingParams: boolean;
  isDirectIp: boolean;
}

export class UrlNormalizer {
  private static readonly TRACKING_PARAMS = new Set([
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'msclkid', 'mc_cid', 'mc_eid', '_ga', '_gl', 'ref', 'source'
  ]);

  /**
   * Normalizes raw URLs into standard canonical format for consistent analysis:
   * 1. Prepends https:// if scheme is missing
   * 2. Lowercases hostname
   * 3. Strips default ports
   * 4. Cleans tracking query parameters
   * 5. Standardizes trailing slashes and paths
   */
  normalize(rawUrl: string): NormalizedUrlResult {
    let formatted = rawUrl.trim();
    if (!/^https?:\/\//i.test(formatted)) {
      formatted = `https://${formatted}`;
    }

    try {
      const parsed = new URL(formatted);
      const protocol = parsed.protocol.toLowerCase() as 'http:' | 'https:';
      const hostname = parsed.hostname.toLowerCase();

      // Remove default ports
      if ((protocol === 'http:' && parsed.port === '80') || (protocol === 'https:' && parsed.port === '443')) {
        parsed.port = '';
      }

      // Check and strip tracking parameters
      let hasTrackingParams = false;
      const cleanParams = new URLSearchParams();
      parsed.searchParams.forEach((val, key) => {
        if (UrlNormalizer.TRACKING_PARAMS.has(key.toLowerCase())) {
          hasTrackingParams = true;
        } else {
          cleanParams.append(key, val);
        }
      });
      parsed.search = cleanParams.toString() ? `?${cleanParams.toString()}` : '';
      parsed.hash = '';

      // Clean pathname
      let pathname = parsed.pathname.replace(/\/+/g, '/');
      if (pathname.endsWith('/') && pathname !== '/') {
        pathname = pathname.slice(0, -1);
      }
      parsed.pathname = pathname;

      // Extract TLD and domain
      const parts = hostname.split('.');
      const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith('[');
      let domain = hostname;
      let tld = '';
      let subdomain: string | undefined = undefined;

      if (!isDirectIp && parts.length >= 2) {
        tld = parts[parts.length - 1];
        // Handle compound ccTLDs like .co.uk, .com.kh, .gov.kh
        const secondTld = parts[parts.length - 2];
        const isCompound = ['co', 'com', 'gov', 'edu', 'org', 'net'].includes(secondTld) && parts.length >= 3;
        if (isCompound) {
          domain = parts.slice(-3).join('.');
          tld = `${secondTld}.${tld}`;
          if (parts.length > 3) {
            subdomain = parts.slice(0, -3).join('.');
          }
        } else {
          domain = parts.slice(-2).join('.');
          if (parts.length > 2) {
            subdomain = parts.slice(0, -2).join('.');
          }
        }
      }

      let normalizedUrl = parsed.toString();
      if (normalizedUrl.endsWith('/') && (pathname === '/' || pathname === '') && !parsed.search && !parsed.hash) {
        normalizedUrl = normalizedUrl.slice(0, -1);
      }

      return {
        rawUrl,
        normalizedUrl,
        protocol,
        hostname,
        domain,
        subdomain,
        tld,
        port: parsed.port || undefined,
        pathname,
        hasTrackingParams,
        isDirectIp,
      };
    } catch {
      return {
        rawUrl,
        normalizedUrl: rawUrl,
        protocol: 'https:',
        hostname: rawUrl,
        domain: rawUrl,
        tld: '',
        pathname: '/',
        hasTrackingParams: false,
        isDirectIp: false,
      };
    }
  }
}

export const urlNormalizer = new UrlNormalizer();
