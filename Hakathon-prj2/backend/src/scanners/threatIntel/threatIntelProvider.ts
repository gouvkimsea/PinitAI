import axios from 'axios';
import { DetectionItem } from '../../types';
import { logger } from '../../utils/logger';
import { config } from '../../config';
import prisma from '../../database/client';
import { LruCache } from '../../utils/lruCache';

export interface ThreatIntelResult {
  provider: string;
  isMalicious: boolean;
  isSuspicious: boolean;
  reputationScore: number;
  detectionsCount: number;
  totalEngines: number;
  threatCategory?: string;
  detections: DetectionItem[];
  raw?: Record<string, unknown>;
}

export interface IThreatIntelProvider {
  name: string;
  isAvailable(): boolean;
  lookupHash(sha256: string): Promise<ThreatIntelResult | null>;
  lookupDomain(domain: string): Promise<ThreatIntelResult | null>;
  lookupUrl(url: string): Promise<ThreatIntelResult | null>;
}

/**
 * VirusTotal API v3 Provider
 */
export class VirusTotalProvider implements IThreatIntelProvider {
  name = 'VirusTotal';
  private apiKey: string;
  private readonly requestTimeoutMs = 3500;

  constructor(apiKey = config.virusTotalApiKey) {
    this.apiKey = apiKey;
  }

  isAvailable(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 10);
  }

  async lookupHash(sha256: string): Promise<ThreatIntelResult | null> {
    if (!this.isAvailable()) return null;

    try {
      const response = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`, {
        headers: { 'x-apikey': this.apiKey },
        timeout: this.requestTimeoutMs,
      });

      const stats = response.data?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = (stats.harmless || 0) + (stats.undetected || 0) + malicious + suspicious;

      const detections: DetectionItem[] = [];
      if (malicious > 0) {
        detections.push({
          engine: 'VirusTotal',
          category: 'threat_reputation',
          severity: malicious > 3 ? 'critical' : 'high',
          ruleId: 'VT-HASH-001',
          title: `VirusTotal Flagged Hash: ${malicious}/${total} Engines`,
          description: `Identified by ${malicious} security vendors on VirusTotal as malicious.`,
          details: { malicious, suspicious, total },
        });
      }

      return {
        provider: this.name,
        isMalicious: malicious > 0,
        isSuspicious: suspicious > 0,
        reputationScore: Math.min(100, Math.round((malicious / Math.max(1, total)) * 100)),
        detectionsCount: malicious + suspicious,
        totalEngines: total,
        threatCategory: malicious > 0 ? 'known_malware' : undefined,
        detections,
        raw: response.data?.data?.attributes,
      };
    } catch (err) {
      logger.debug('VirusTotal hash lookup failed or not found', { sha256, error: (err as Error).message });
      return null;
    }
  }

  async lookupDomain(domain: string): Promise<ThreatIntelResult | null> {
    if (!this.isAvailable()) return null;

    try {
      const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
        headers: { 'x-apikey': this.apiKey },
        timeout: this.requestTimeoutMs,
      });

      const stats = response.data?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = (stats.harmless || 0) + (stats.undetected || 0) + malicious + suspicious;

      const detections: DetectionItem[] = [];
      if (malicious > 0) {
        detections.push({
          engine: 'VirusTotal',
          category: 'domain_reputation',
          severity: malicious > 2 ? 'critical' : 'high',
          ruleId: 'VT-DOM-001',
          title: `VirusTotal Domain Blacklist (${malicious}/${total} engines)`,
          description: `Domain ${domain} flagged as malicious by threat intelligence providers.`,
          details: { malicious, total },
        });
      }

      return {
        provider: this.name,
        isMalicious: malicious > 0,
        isSuspicious: suspicious > 0,
        reputationScore: Math.min(100, Math.round((malicious / Math.max(1, total)) * 100)),
        detectionsCount: malicious + suspicious,
        totalEngines: total,
        detections,
        raw: response.data?.data?.attributes,
      };
    } catch (err) {
      logger.debug('VirusTotal domain lookup failed', { domain, error: (err as Error).message });
      return null;
    }
  }

  async lookupUrl(rawUrl: string): Promise<ThreatIntelResult | null> {
    if (!this.isAvailable()) return null;

    try {
      // VirusTotal URL ID is base64 without padding
      const urlId = Buffer.from(rawUrl).toString('base64').replace(/=/g, '');
      const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { 'x-apikey': this.apiKey },
        timeout: this.requestTimeoutMs,
      });

      const stats = response.data?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = (stats.harmless || 0) + (stats.undetected || 0) + malicious + suspicious;

      const detections: DetectionItem[] = [];
      if (malicious > 0) {
        detections.push({
          engine: 'VirusTotal',
          category: 'url_reputation',
          severity: 'critical',
          ruleId: 'VT-URL-001',
          title: `VirusTotal Flagged URL (${malicious}/${total} Engines)`,
          description: `URL flagged as malicious or phishing by ${malicious} security vendors.`,
        });
      }

      return {
        provider: this.name,
        isMalicious: malicious > 0,
        isSuspicious: suspicious > 0,
        reputationScore: Math.min(100, Math.round((malicious / Math.max(1, total)) * 100)),
        detectionsCount: malicious,
        totalEngines: total,
        detections,
      };
    } catch (err) {
      logger.debug('VirusTotal URL lookup failed', { error: (err as Error).message });
      return null;
    }
  }
}

/**
 * Built-in Threat Intelligence Provider for offline testing and standard control samples.
 */
export class LocalSignatureIntelProvider implements IThreatIntelProvider {
  name = 'InternalThreatIntel';

  // Standard EICAR SHA-256 hash
  private KNOWN_MALICIOUS_HASHES = new Map<string, { title: string; category: string }>([
    [
      '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      { title: 'Standard EICAR Antivirus Test Signature', category: 'antivirus_test' },
    ],
    [
      '131f95c51cc819465fa1797f6cc9379108f60f61e80b32433290b2e52c5443cf',
      { title: 'Generic Ransomware Marker', category: 'ransomware' },
    ],
  ]);

  private KNOWN_MALICIOUS_DOMAINS = new Set([
    'phishing-test-login.com',
    'bank-security-update-fake.xyz',
    'malware-test-download.top',
  ]);

  isAvailable(): boolean {
    return true;
  }

  async lookupHash(sha256: string): Promise<ThreatIntelResult | null> {
    const match = this.KNOWN_MALICIOUS_HASHES.get(sha256.toLowerCase());
    if (match) {
      return {
        provider: this.name,
        isMalicious: true,
        isSuspicious: false,
        reputationScore: 100,
        detectionsCount: 1,
        totalEngines: 1,
        threatCategory: match.category,
        detections: [
          {
            engine: this.name,
            category: match.category,
            severity: 'critical',
            ruleId: 'INTEL-HASH-001',
            title: `Known Threat Hash: ${match.title}`,
            description: `File SHA-256 matches verified malicious control sample database (${sha256.substring(0, 12)}...).`,
            details: { sha256, category: match.category },
          },
        ],
      };
    }
    return null;
  }

  async lookupDomain(domain: string): Promise<ThreatIntelResult | null> {
    if (this.KNOWN_MALICIOUS_DOMAINS.has(domain.toLowerCase())) {
      return {
        provider: this.name,
        isMalicious: true,
        isSuspicious: false,
        reputationScore: 95,
        detectionsCount: 1,
        totalEngines: 1,
        threatCategory: 'phishing',
        detections: [
          {
            engine: this.name,
            category: 'phishing',
            severity: 'critical',
            ruleId: 'INTEL-DOM-001',
            title: `Known Blacklisted Domain: ${domain}`,
            description: 'Domain is cataloged in the internal threat intelligence indicator feed.',
          },
        ],
      };
    }
    return null;
  }

  async lookupUrl(url: string): Promise<ThreatIntelResult | null> {
    try {
      const parsed = new URL(url);
      return this.lookupDomain(parsed.hostname);
    } catch {
      return null;
    }
  }
}

/**
 * Threat Intelligence Aggregator & Cache Manager with Dual-Layer Caching (Memory + Database)
 */
export class ThreatIntelManager {
  private providers: IThreatIntelProvider[] = [];
  private hashMemoryCache = new LruCache<string, ThreatIntelResult | null>({ maxSize: 2000, defaultTtlMs: 10 * 60 * 1000 });
  private domainMemoryCache = new LruCache<string, ThreatIntelResult | null>({ maxSize: 2000, defaultTtlMs: 10 * 60 * 1000 });

  constructor() {
    this.providers.push(new LocalSignatureIntelProvider());
    this.providers.push(new VirusTotalProvider());
  }

  async checkHash(sha256: string): Promise<ThreatIntelResult | null> {
    const normalizedHash = sha256.toLowerCase();

    // 1. Check in-memory LRU cache (fastest, 0ms)
    const memCached = this.hashMemoryCache.get(normalizedHash);
    if (memCached !== undefined) {
      return memCached;
    }

    // 2. Check local DB cache (TTL 24 hours)
    try {
      const cached = await prisma.threatIntelligence.findFirst({
        where: {
          targetType: 'HASH',
          targetValue: normalizedHash,
          expiresAt: { gt: new Date() },
        },
      });

      if (cached && cached.rawData) {
        const parsed = JSON.parse(cached.rawData) as ThreatIntelResult;
        this.hashMemoryCache.set(normalizedHash, parsed);
        return parsed;
      }
    } catch (e) {
      logger.debug('DB Cache query skipped', { error: (e as Error).message });
    }

    // 3. Query active providers
    for (const provider of this.providers) {
      if (provider.isAvailable()) {
        const result = await provider.lookupHash(normalizedHash);
        if (result && result.isMalicious) {
          this.hashMemoryCache.set(normalizedHash, result);
          // Cache in DB
          try {
            await prisma.threatIntelligence.create({
              data: {
                targetType: 'HASH',
                targetValue: normalizedHash,
                provider: provider.name,
                reputationScore: result.reputationScore,
                threatCategory: result.threatCategory,
                rawData: JSON.stringify(result),
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
              },
            });
          } catch {
            // Ignore cache write collision
          }
          return result;
        }
      }
    }

    this.hashMemoryCache.set(normalizedHash, null);
    return null;
  }

  async checkDomain(domain: string): Promise<ThreatIntelResult | null> {
    const normalizedDomain = domain.toLowerCase().trim();

    // 1. Check in-memory LRU cache (fastest, 0ms)
    const memCached = this.domainMemoryCache.get(normalizedDomain);
    if (memCached !== undefined) {
      return memCached;
    }

    // 2. Check persistent DB cache (TTL 24 hours) — survives process restarts
    try {
      const dbCached = await prisma.threatIntelligence.findFirst({
        where: {
          targetType: 'DOMAIN',
          targetValue: normalizedDomain,
          expiresAt: { gt: new Date() },
        },
      });
      if (dbCached && dbCached.rawData) {
        const parsed = JSON.parse(dbCached.rawData) as ThreatIntelResult;
        this.domainMemoryCache.set(normalizedDomain, parsed);
        return parsed;
      }
    } catch (e) {
      logger.debug('Domain DB cache query skipped', { error: (e as Error).message });
    }

    // 3. Query active providers
    for (const provider of this.providers) {
      if (provider.isAvailable()) {
        const result = await provider.lookupDomain(normalizedDomain);
        if (result && result.isMalicious) {
          this.domainMemoryCache.set(normalizedDomain, result);
          // Persist positive (malicious) results to DB cache
          try {
            await prisma.threatIntelligence.create({
              data: {
                targetType: 'DOMAIN',
                targetValue: normalizedDomain,
                provider: provider.name,
                reputationScore: result.reputationScore,
                threatCategory: result.threatCategory,
                rawData: JSON.stringify(result),
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
              },
            });
          } catch {
            // Ignore cache write collision
          }
          return result;
        }
      }
    }

    this.domainMemoryCache.set(normalizedDomain, null);
    return null;
  }
}

export const threatIntel = new ThreatIntelManager();

