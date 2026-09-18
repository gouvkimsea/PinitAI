/**
 * Pinit Domain Age & WHOIS/RDAP Service
 * Evaluates domain registration age, creation dates, registrar details, and privacy flags.
 * Includes LRU caching, strict 1.5s timeout protection, and non-blocking failure recovery.
 */

import axios from 'axios';
import { LruCache } from '../../utils/lruCache';
import { logger } from '../../utils/logger';
import { DomainAgeInfo } from './types';
import { httpsAgent } from '../../utils/httpConnectionPool';
import { rdapCircuitBreaker } from '../ai/circuitBreaker';
import { metricsCollector } from '../monitoring/metricsCollector';

const RDAP_TIMEOUT_MS = 1500;
const NEW_DOMAIN_THRESHOLD_DAYS = 30;

export const domainAgeCache = new LruCache<string, DomainAgeInfo>({
  maxSize: 2000,
  defaultTtlMs: 24 * 60 * 60 * 1000, // 24 hours TTL
});

export class DomainAgeService {
  // Pre-configured well-known domain creation dates for instant zero-network testing and top domains
  private static readonly KNOWN_DOMAINS: Record<string, { creationDate: string; registrar: string }> = {
    'google.com': { creationDate: '1997-09-15', registrar: 'MarkMonitor Inc.' },
    'github.com': { creationDate: '2007-10-09', registrar: 'MarkMonitor Inc.' },
    'wikipedia.org': { creationDate: '2001-01-13', registrar: 'MarkMonitor Inc.' },
    'paypal.com': { creationDate: '1999-07-15', registrar: 'MarkMonitor Inc.' },
    'microsoft.com': { creationDate: '1991-05-02', registrar: 'MarkMonitor Inc.' },
    'apple.com': { creationDate: '1987-02-19', registrar: 'CSC Corporate Domains' },
    'amazon.com': { creationDate: '1994-11-01', registrar: 'MarkMonitor Inc.' },
    'ababank.com': { creationDate: '2000-01-12', registrar: 'CSC Corporate Domains' },
    'acledabank.com.kh': { creationDate: '2001-08-01', registrar: 'Telecommunication Cambodia' },
    'wingmoney.com': { creationDate: '2009-03-24', registrar: 'GoDaddy.com LLC' },
  };

  /**
   * Retrieves domain age and WHOIS/RDAP details for a root/base domain.
   */
  async getDomainAgeInfo(baseDomain: string): Promise<DomainAgeInfo> {
    const domain = (baseDomain || '').toLowerCase().trim();
    if (!domain || domain.includes('/') || /^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
      return { evaluated: false };
    }

    // 1. Cache hit
    const cached = domainAgeCache.get(domain);
    if (cached) {
      metricsCollector.recordCacheLookup(true);
      return { ...cached, cached: true };
    }

    // 2. Known static domain metadata
    if (DomainAgeService.KNOWN_DOMAINS[domain]) {
      const known = DomainAgeService.KNOWN_DOMAINS[domain];
      const creationTime = new Date(known.creationDate).getTime();
      const ageDays = Math.floor((Date.now() - creationTime) / (1000 * 60 * 60 * 24));
      const res: DomainAgeInfo = {
        evaluated: true,
        domainAgeDays: ageDays,
        isNewDomain: ageDays <= NEW_DOMAIN_THRESHOLD_DAYS,
        creationDate: known.creationDate,
        registrar: known.registrar,
        privacyProtected: false,
        cached: false,
      };
      domainAgeCache.set(domain, res);
      metricsCollector.recordCacheLookup(true);
      return res;
    }

    metricsCollector.recordCacheLookup(false);

    // In test environment, avoid slow external public rate-limited network queries unless explicitly opted-in
    if (process.env.NODE_ENV === 'test' && !process.env.ENABLE_REAL_RDAP_IN_TESTS) {
      return {
        evaluated: false,
        error: 'Outbound RDAP network queries disabled in test environment.',
      };
    }

    // Fast-fail if circuit breaker is OPEN
    if (rdapCircuitBreaker.isOpen()) {
      logger.debug('RDAP circuit breaker is OPEN — bypassing outbound WHOIS request', { domain });
      return {
        evaluated: false,
        error: 'RDAP service currently offline or degraded (circuit breaker OPEN).',
      };
    }

    // 3. Query RDAP endpoint (Registration Data Access Protocol)
    const startTime = Date.now();
    try {
      const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
      const response = await axios.get(rdapUrl, {
        httpsAgent,
        timeout: RDAP_TIMEOUT_MS,
        headers: {
          'Accept': 'application/rdap+json, application/json',
          'User-Agent': 'PinIt-Security-Scanner/1.0',
        },
      });

      const duration = Date.now() - startTime;
      rdapCircuitBreaker.recordSuccess();
      metricsCollector.recordExternalApiCall(duration, true);

      if (response.status === 200 && response.data) {
        const data = response.data;
        let creationDate: string | undefined;
        let expirationDate: string | undefined;

        // Parse events
        if (Array.isArray(data.events)) {
          for (const ev of data.events) {
            if (ev.eventAction === 'registration') {
              creationDate = ev.eventDate;
            } else if (ev.eventAction === 'expiration') {
              expirationDate = ev.eventDate;
            }
          }
        }

        // Registrar
        let registrar: string | undefined;
        if (Array.isArray(data.entities)) {
          for (const ent of data.entities) {
            if (Array.isArray(ent.roles) && ent.roles.includes('registrar')) {
              registrar = ent.vcardArray?.[1]?.find((item: any) => item[0] === 'fn')?.[3] || ent.handle;
            }
          }
        }

        // Check privacy protection
        const serialized = JSON.stringify(data).toLowerCase();
        const privacyProtected =
          serialized.includes('privacy') ||
          serialized.includes('whoisguard') ||
          serialized.includes('redacted for privacy') ||
          serialized.includes('withheld for privacy');

        let ageDays: number | undefined;
        let isNewDomain = false;

        if (creationDate) {
          const creationTime = new Date(creationDate).getTime();
          if (!isNaN(creationTime)) {
            ageDays = Math.max(0, Math.floor((Date.now() - creationTime) / (1000 * 60 * 60 * 24)));
            isNewDomain = ageDays <= NEW_DOMAIN_THRESHOLD_DAYS;
          }
        }

        const result: DomainAgeInfo = {
          evaluated: true,
          domainAgeDays: ageDays,
          isNewDomain,
          creationDate,
          expirationDate,
          registrar,
          privacyProtected,
          cached: false,
        };

        domainAgeCache.set(domain, result);
        return result;
      }
    } catch (err: any) {
      const duration = Date.now() - startTime;
      rdapCircuitBreaker.recordFailure((err as Error).message);
      metricsCollector.recordExternalApiCall(duration, false);
      logger.debug('RDAP lookup was unavailable or timed out', { domain, error: (err as Error).message });
    }

    // Graceful fallback when RDAP is unreachable or unconfigured
    const fallback: DomainAgeInfo = {
      evaluated: false,
      error: 'Domain age information was not accessible within timeout threshold.',
    };
    return fallback;
  }

  /**
   * Utility for tests to register synthetic domain age info
   */
  setMockDomainAge(domain: string, ageDays: number, registrar = 'Test Registrar') {
    const creationTime = Date.now() - ageDays * 24 * 60 * 60 * 1000;
    const info: DomainAgeInfo = {
      evaluated: true,
      domainAgeDays: ageDays,
      isNewDomain: ageDays <= NEW_DOMAIN_THRESHOLD_DAYS,
      creationDate: new Date(creationTime).toISOString().split('T')[0],
      registrar,
      privacyProtected: false,
      cached: false,
    };
    domainAgeCache.set(domain.toLowerCase(), info);
  }
}

export const domainAgeService = new DomainAgeService();
