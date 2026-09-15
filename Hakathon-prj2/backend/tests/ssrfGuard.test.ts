import { describe, it, expect } from 'vitest';
import { isPrivateOrReservedIpv4, isPrivateOrReservedIpv6, validateUrlForSsrf } from '../src/scanners/url/ssrfGuard';

describe('SSRF Guard', () => {
  it('should identify private and loopback IPv4 ranges', () => {
    expect(isPrivateOrReservedIpv4('127.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIpv4('127.10.0.5')).toBe(true);
    expect(isPrivateOrReservedIpv4('10.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIpv4('192.168.1.100')).toBe(true);
    expect(isPrivateOrReservedIpv4('172.16.0.1')).toBe(true);
    expect(isPrivateOrReservedIpv4('172.31.255.255')).toBe(true);
    // Cloud metadata endpoint
    expect(isPrivateOrReservedIpv4('169.254.169.254')).toBe(true);

    // Public IPs should pass
    expect(isPrivateOrReservedIpv4('8.8.8.8')).toBe(false);
    expect(isPrivateOrReservedIpv4('1.1.1.1')).toBe(false);
    expect(isPrivateOrReservedIpv4('142.250.190.46')).toBe(false);
  });

  it('should identify private and loopback IPv6 ranges', () => {
    expect(isPrivateOrReservedIpv6('::1')).toBe(true);
    expect(isPrivateOrReservedIpv6('fe80::1')).toBe(true);
    expect(isPrivateOrReservedIpv6('fc00::1')).toBe(true);
    expect(isPrivateOrReservedIpv6('::ffff:127.0.0.1')).toBe(true);
  });

  it('should block direct SSRF URL attempts to metadata and loopback', async () => {
    const metadataCheck = await validateUrlForSsrf('http://169.254.169.254/latest/meta-data/');
    expect(metadataCheck.isSafe).toBe(false);
    expect(metadataCheck.blockedReason).toContain('SSRF');

    const loopbackCheck = await validateUrlForSsrf('http://127.0.0.1:8080/admin');
    expect(loopbackCheck.isSafe).toBe(false);

    const localhostCheck = await validateUrlForSsrf('http://localhost:3000');
    expect(localhostCheck.isSafe).toBe(false);
  });

  it('should reject non-HTTP protocols such as file:// and gopher://', async () => {
    const fileCheck = await validateUrlForSsrf('file:///etc/passwd');
    expect(fileCheck.isSafe).toBe(false);

    const gopherCheck = await validateUrlForSsrf('gopher://127.0.0.1:6379');
    expect(gopherCheck.isSafe).toBe(false);
  });
});
