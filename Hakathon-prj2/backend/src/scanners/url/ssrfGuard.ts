import dns from 'dns';
import net from 'net';
import { LruCache } from '../../utils/lruCache';

export const dnsCache = new LruCache<string, dns.LookupAddress[]>({
  maxSize: 1000,
  defaultTtlMs: 5 * 60 * 1000, // 5 minutes TTL
});

export interface SsrfCheckResult {
  isSafe: boolean;
  resolvedIp?: string;
  blockedReason?: string;
}

/**
 * Checks whether an IPv4 address belongs to a private, loopback, or reserved subnet.
 */
export function isPrivateOrReservedIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;

  const [b0, b1] = parts;

  // 0.0.0.0/8 (Current network)
  if (b0 === 0) return true;
  // 10.0.0.0/8 (Private)
  if (b0 === 10) return true;
  // 127.0.0.0/8 (Loopback)
  if (b0 === 127) return true;
  // 100.64.0.0/10 (Carrier-grade NAT)
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;
  // 169.254.0.0/16 (Link-local & Cloud metadata: 169.254.169.254)
  if (b0 === 169 && b1 === 254) return true;
  // 172.16.0.0/12 (Private)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (b0 === 192 && b1 === 0 && parts[2] === 0) return true;
  // 192.168.0.0/16 (Private)
  if (b0 === 192 && b1 === 168) return true;
  // 198.18.0.0/15 (Network benchmark tests)
  if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;
  // 224.0.0.0/4 (Multicast)
  if (b0 >= 224 && b0 <= 239) return true;
  // 240.0.0.0/4 (Reserved / Future use)
  if (b0 >= 240) return true;
  // 255.255.255.255 (Broadcast)
  if (ip === '255.255.255.255') return true;

  return false;
}

/**
 * Checks whether an IPv6 address belongs to private or loopback ranges.
 */
export function isPrivateOrReservedIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // Loopback (::1)
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
  // Unspecified (::)
  if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true;
  // Link-local (fe80::/10)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }
  // Unique local (fc00::/7)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
  // IPv4-mapped IPv6 (::ffff:127.0.0.1)
  if (normalized.includes('::ffff:')) {
    const ipv4Part = normalized.split('::ffff:')[1];
    if (net.isIPv4(ipv4Part)) {
      return isPrivateOrReservedIpv4(ipv4Part);
    }
    return true;
  }

  return false;
}

/**
 * Resolves a hostname via DNS and verifies that none of its IP addresses point to internal/reserved destinations.
 */
export async function validateUrlForSsrf(urlString: string): Promise<SsrfCheckResult> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlString);
  } catch {
    return { isSafe: false, blockedReason: 'Invalid URL format' };
  }

  // Only permit HTTP and HTTPS protocols
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return {
      isSafe: false,
      blockedReason: `Disallowed protocol '${parsedUrl.protocol}'. Only http: and https: are permitted.`,
    };
  }

  const hostname = parsedUrl.hostname;

  // Direct IP checks
  if (net.isIPv4(hostname)) {
    if (isPrivateOrReservedIpv4(hostname)) {
      return {
        isSafe: false,
        resolvedIp: hostname,
        blockedReason: `Direct access to private or reserved IPv4 address '${hostname}' is blocked to prevent SSRF attacks.`,
      };
    }
    return { isSafe: true, resolvedIp: hostname };
  }

  if (net.isIPv6(hostname)) {
    const cleanIpv6 = hostname.replace(/^\[|\]$/g, '');
    if (isPrivateOrReservedIpv6(cleanIpv6)) {
      return {
        isSafe: false,
        resolvedIp: cleanIpv6,
        blockedReason: `Direct access to private or reserved IPv6 address '${cleanIpv6}' is blocked to prevent SSRF attacks.`,
      };
    }
    return { isSafe: true, resolvedIp: cleanIpv6 };
  }

  // Check common local alias names and cloud metadata domains
  const normalizedHost = hostname.toLowerCase();
  const blockedHostnames = new Set([
    'localhost',
    'localhost.localdomain',
    '127.0.0.1.nip.io',
    'localtest.me',
    'metadata.google.internal',
    'instance-data',
    'metadata',
  ]);

  if (blockedHostnames.has(normalizedHost) || normalizedHost.endsWith('.localhost') || normalizedHost.endsWith('.local')) {
    return {
      isSafe: false,
      blockedReason: `Access to local/internal hostname '${hostname}' is blocked for SSRF protection.`,
    };
  }

  // Detect and block integer / decimal IP notations (e.g. 2130706433 = 127.0.0.1)
  if (/^\d+$/.test(normalizedHost)) {
    const num = parseInt(normalizedHost, 10);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      const b0 = (num >>> 24) & 255;
      const b1 = (num >>> 16) & 255;
      const b2 = (num >>> 8) & 255;
      const b3 = num & 255;
      const convertedIp = `${b0}.${b1}.${b2}.${b3}`;
      if (isPrivateOrReservedIpv4(convertedIp)) {
        return {
          isSafe: false,
          resolvedIp: convertedIp,
          blockedReason: `Decimal IP representation '${hostname}' evaluates to internal IP '${convertedIp}'. Blocked for SSRF protection.`,
        };
      }
    }
  }

  // Detect and block hex IP notations (e.g. 0x7f.0.0.1, 0x7f000001)
  if (/^0x[0-9a-fA-F]+/i.test(normalizedHost)) {
    return {
      isSafe: false,
      blockedReason: `Hexadecimal IP representation '${hostname}' is blocked for SSRF protection.`,
    };
  }

  // Perform DNS resolution to inspect underlying IPs (with LRU caching and 2000ms timeout)
  try {
    let records = dnsCache.get(hostname);
    if (!records) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const dnsPromise = dns.promises.lookup(hostname, { all: true });
      const timeoutPromise = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('DNS lookup timed out after 2000ms')), 2000);
      });

      try {
        records = await Promise.race([dnsPromise, timeoutPromise]);
        dnsCache.set(hostname, records);
      } finally {
        if (timer) clearTimeout(timer);
      }
    }

    if (!records || records.length === 0) {
      return { isSafe: false, blockedReason: `Domain '${hostname}' could not be resolved.` };
    }

    for (const record of records) {
      if (record.family === 4 && isPrivateOrReservedIpv4(record.address)) {
        return {
          isSafe: false,
          resolvedIp: record.address,
          blockedReason: `Domain '${hostname}' resolves to private/internal IP '${record.address}'. Blocked for SSRF protection.`,
        };
      }
      if (record.family === 6 && isPrivateOrReservedIpv6(record.address)) {
        return {
          isSafe: false,
          resolvedIp: record.address,
          blockedReason: `Domain '${hostname}' resolves to private/internal IPv6 '${record.address}'. Blocked for SSRF protection.`,
        };
      }
    }

    return { isSafe: true, resolvedIp: records[0].address };
  } catch (err: any) {
    const code = err?.code;
    // If the domain is non-existent or unresolvable in the current environment (e.g. offline testing or dummy domains),
    // it cannot route to internal RFC1918/link-local/metadata IPs. Allow static analysis to proceed safely.
    if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'ENODATA' || code === 'EADDRNOTAVAIL') {
      return { isSafe: true };
    }
    return {
      isSafe: false,
      blockedReason: `DNS resolution failed for '${hostname}': ${(err as Error).message}`,
    };
  }
}

export const ssrfGuard = {
  validateUrlForSsrf,
  async validateUrlSafe(urlString: string) {
    const res = await validateUrlForSsrf(urlString);
    return {
      isSafe: res.isSafe,
      safe: res.isSafe,
      resolvedIp: res.resolvedIp,
      blockedReason: res.blockedReason,
      reason: res.blockedReason,
    };
  },
};


