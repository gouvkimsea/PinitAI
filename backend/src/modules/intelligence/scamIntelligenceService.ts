import { v4 as uuidv4 } from 'uuid';
import { prisma } from '../../database/client';
import { logger } from '../../utils/logger';
import { DEFAULT_SCAM_PATTERNS } from './defaultCatalog';
import {
  ScamPatternRecord,
  CreatePatternInput,
  UpdatePatternInput,
  PatternQueryFilter,
  PatternMatch,
  ContentComparisonOptions,
  ContentComparisonResult,
  PatternSeverity,
  PatternStatus,
} from './types';

interface CachedPattern {
  record: ScamPatternRecord;
  regex: RegExp;
  weight: number;
}

export class ScamIntelligenceService {
  private static instance: ScamIntelligenceService | null = null;
  private isInitialized = false;
  private initPromise: Promise<void> | null = null;
  private cache: CachedPattern[] = [];
  private lastCacheRefresh = 0;
  private readonly CACHE_TTL_MS = 60_000; // 1 minute background freshness guarantee

  private constructor() {}

  public static getInstance(): ScamIntelligenceService {
    if (!ScamIntelligenceService.instance) {
      ScamIntelligenceService.instance = new ScamIntelligenceService();
    }
    return ScamIntelligenceService.instance;
  }

  /**
   * Initializes the SQLite persistence table and loads patterns into the fast in-memory regex index.
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      try {
        await this.ensureTableSchema();
        await this.seedDefaultCatalogIfEmpty();
        await this.refreshCache();
        this.isInitialized = true;
        logger.info('ScamIntelligenceService initialized successfully', {
          cachedPatternsCount: this.cache.length,
        });
      } catch (err) {
        logger.error('Failed to initialize ScamIntelligenceService', { error: err });
        // Fallback: load default catalog in-memory so detection keeps working even if DB is temporarily locked
        this.loadInMemoryFallback();
        this.isInitialized = true;
      } finally {
        this.initPromise = null;
      }
    })();

    return this.initPromise;
  }

  /**
   * Creates the scam_patterns table in SQLite if it does not already exist.
   */
  private async ensureTableSchema(): Promise<void> {
    // Schema is managed declaratively by Prisma migrations (PostgreSQL / SQLite agnostic)
  }

  /**
   * Seeds the default catalog of 10 categories if table is currently empty.
   */
  public async seedDefaultCatalogIfEmpty(): Promise<number> {
    try {
      const total = await prisma.scamPattern.count();
      if (total === 0) {
        return (await this.seedCatalog(false)).count;
      }
      return total;
    } catch (err) {
      logger.warn('Could not query scam_patterns count, proceeding with seed check', { error: err });
      return 0;
    }
  }

  /**
   * Seeds the catalog into the database.
   */
  public async seedCatalog(forceReset = false): Promise<{ count: number }> {
    await this.ensureTableSchema();

    if (forceReset) {
      await prisma.scamPattern.deleteMany();
    }

    let inserted = 0;

    for (const item of DEFAULT_SCAM_PATTERNS) {
      const id = item.id || uuidv4();
      const status = item.status || 'active';

      try {
        if (forceReset) {
          await prisma.scamPattern.create({
            data: {
              id,
              pattern: item.pattern,
              category: item.category,
              severity: item.severity,
              description: item.description,
              source: item.source,
              status,
            },
          });
          inserted++;
        } else {
          const existing = await prisma.scamPattern.findFirst({
            where: { pattern: item.pattern },
            select: { id: true },
          });
          if (!existing) {
            await prisma.scamPattern.create({
              data: {
                id,
                pattern: item.pattern,
                category: item.category,
                severity: item.severity,
                description: item.description,
                source: item.source,
                status,
              },
            });
            inserted++;
          }
        }
      } catch (err) {
        logger.warn('Error inserting seed pattern', { pattern: item.pattern, error: err });
      }
    }

    await this.refreshCache();
    return { count: inserted };
  }

  /**
   * Refreshes the in-memory compiled regex cache from the database.
   */
  public async refreshCache(): Promise<void> {
    try {
      const rows = await prisma.scamPattern.findMany({
        where: { status: 'active' },
        orderBy: { createdAt: 'desc' },
      });

      this.cache = this.compileRecords(
        rows.map((r) => ({
          ...r,
          severity: r.severity as PatternSeverity,
          status: r.status as PatternStatus,
          createdAt: r.createdAt.toISOString(),
          updatedAt: r.updatedAt.toISOString(),
        }))
      );
      this.lastCacheRefresh = Date.now();
    } catch (err) {
      logger.error('Failed to refresh scam intelligence cache from database', { error: err });
      if (this.cache.length === 0) {
        this.loadInMemoryFallback();
      }
    }
  }

  private loadInMemoryFallback(): void {
    const now = new Date().toISOString();
    const fallbackRecords: ScamPatternRecord[] = DEFAULT_SCAM_PATTERNS.map((item, index) => ({
      id: item.id || `intel-fb-${index}`,
      pattern: item.pattern,
      category: item.category,
      severity: item.severity,
      description: item.description,
      source: item.source,
      status: item.status || 'active',
      createdAt: now,
      updatedAt: now,
    }));
    this.cache = this.compileRecords(fallbackRecords);
    this.lastCacheRefresh = Date.now();
  }

  private compileRecords(records: ScamPatternRecord[]): CachedPattern[] {
    const compiled: CachedPattern[] = [];

    for (const record of records) {
      try {
        // Compile regex safely (case-insensitive)
        const regex = new RegExp(record.pattern, 'i');
        const weight = this.severityToWeight(record.severity);
        compiled.push({ record, regex, weight });
      } catch (err) {
        logger.warn('Failed to compile regex pattern, falling back to escaped literal', {
          id: record.id,
          pattern: record.pattern,
          error: err,
        });
        const escaped = record.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        compiled.push({
          record,
          regex: new RegExp(escaped, 'i'),
          weight: this.severityToWeight(record.severity),
        });
      }
    }

    return compiled;
  }

  private severityToWeight(severity: PatternSeverity): number {
    switch (severity) {
      case 'critical':
        return 45;
      case 'high':
        return 35;
      case 'medium':
        return 20;
      case 'low':
      default:
        return 10;
    }
  }

  // =========================================================================
  // Comparison & Detection Service
  // =========================================================================

  /**
   * Compares submitted content against known scam patterns in the database.
   * Runs in sub-millisecond time via the cached compiled regex index.
   */
  public async matchContent(
    content: string,
    options?: ContentComparisonOptions
  ): Promise<ContentComparisonResult> {
    await this.initialize();

    // Auto-refresh cache if TTL expired
    if (Date.now() - this.lastCacheRefresh > this.CACHE_TTL_MS) {
      this.refreshCache().catch((err) => logger.warn('Background cache refresh failed', { error: err }));
    }

    const startTime = Date.now();
    const cleanText = (content || '').trim();

    if (!cleanText) {
      return {
        matched: false,
        matched_patterns: [],
        categories_detected: [],
        highest_severity: 'safe',
        scam_score: 0,
        recommended_action: 'No content provided to evaluate.',
        evaluated_pattern_count: this.cache.length,
        execution_time_ms: Date.now() - startTime,
      };
    }

    const matchedPatterns: PatternMatch[] = [];
    let accumulatedScore = 0;
    let highestSeverityLevel = 0; // 0=safe, 1=low, 2=medium, 3=high, 4=critical

    const severityRanks: Record<PatternSeverity, number> = {
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };

    const targetCategories = options?.categories && options.categories.length > 0
      ? new Set(options.categories.map((c) => c.toLowerCase()))
      : null;

    const minSeverityRank = options?.minSeverity ? severityRanks[options.minSeverity] : 1;
    const maxMatches = options?.maxMatches || 20;

    for (const item of this.cache) {
      if (targetCategories && !targetCategories.has(item.record.category.toLowerCase())) {
        continue;
      }

      const itemSeverityRank = severityRanks[item.record.severity] || 1;
      if (itemSeverityRank < minSeverityRank) {
        continue;
      }

      const match = item.regex.exec(cleanText);
      if (match) {
        matchedPatterns.push({
          id: item.record.id,
          pattern: item.record.pattern,
          category: item.record.category,
          severity: item.record.severity,
          description: item.record.description,
          source: item.record.source,
          matched_text: match[0],
          weight: item.weight,
        });

        accumulatedScore += item.weight;
        if (itemSeverityRank > highestSeverityLevel) {
          highestSeverityLevel = itemSeverityRank;
        }

        if (matchedPatterns.length >= maxMatches) {
          break;
        }
      }
    }

    const scamScore = Math.min(100, accumulatedScore);
    const categoriesDetected = Array.from(new Set(matchedPatterns.map((p) => p.category)));

    const severityMap: Record<number, PatternSeverity | 'safe'> = {
      0: 'safe',
      1: 'low',
      2: 'medium',
      3: 'high',
      4: 'critical',
    };
    const highestSeverity = severityMap[highestSeverityLevel];

    let recommendedAction = 'No known scam pattern signatures detected. Exercise standard digital hygiene.';
    if (highestSeverity === 'critical') {
      recommendedAction = 'CRITICAL ALERT: Threat matched known high-severity scam patterns (e.g. OTP theft, private key harvest, or law enforcement extortion). Do NOT send money, share codes, or click links.';
    } else if (highestSeverity === 'high') {
      recommendedAction = 'HIGH RISK: Content contains signatures of advance-fee schemes, fake employment, or banking impersonation. Discard message and verify through independent official channels.';
    } else if (highestSeverity === 'medium') {
      recommendedAction = 'SUSPICIOUS: Content exhibits patterns common in deceptive marketing or unverified offers. Proceed with elevated caution.';
    } else if (highestSeverity === 'low') {
      recommendedAction = 'MILD CONCERN: Subtle pattern match detected. Review carefully before taking any action.';
    }

    return {
      matched: matchedPatterns.length > 0,
      matched_patterns: matchedPatterns,
      categories_detected: categoriesDetected,
      highest_severity: highestSeverity,
      scam_score: scamScore,
      recommended_action: recommendedAction,
      evaluated_pattern_count: this.cache.length,
      execution_time_ms: Date.now() - startTime,
    };
  }

  // =========================================================================
  // Database CRUD Operations (Dynamic Updates Without Changing App Code)
  // =========================================================================

  /**
   * Retrieve patterns with optional filtering by category, severity, status, or search query.
   */
  public async getPatterns(filter?: PatternQueryFilter): Promise<{ patterns: ScamPatternRecord[]; total: number }> {
    await this.initialize();

    const where: Record<string, unknown> = {};

    if (filter?.category) {
      where.category = filter.category;
    }
    if (filter?.severity) {
      where.severity = filter.severity;
    }
    if (filter?.status) {
      where.status = filter.status;
    }
    if (filter?.search) {
      where.OR = [
        { pattern: { contains: filter.search, mode: 'insensitive' } },
        { description: { contains: filter.search, mode: 'insensitive' } },
        { source: { contains: filter.search, mode: 'insensitive' } },
      ];
    }

    const limit = filter?.limit ? Math.max(1, Math.min(200, filter.limit)) : 50;
    const offset = filter?.offset ? Math.max(0, filter.offset) : 0;

    const [total, records] = await Promise.all([
      prisma.scamPattern.count({ where }),
      prisma.scamPattern.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
      }),
    ]);

    const patterns: ScamPatternRecord[] = records.map((r) => ({
      ...r,
      severity: r.severity as PatternSeverity,
      status: r.status as PatternStatus,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
    }));

    return { patterns, total };
  }

  /**
   * Get a single scam pattern by ID.
   */
  public async getPatternById(id: string): Promise<ScamPatternRecord | null> {
    await this.initialize();

    const r = await prisma.scamPattern.findUnique({
      where: { id },
    });

    if (!r) return null;

    return {
      ...r,
      severity: r.severity as PatternSeverity,
      status: r.status as PatternStatus,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
    };
  }

  /**
   * Create a new scam pattern. Automatically refreshes cache without restarting the app.
   */
  public async createPattern(input: CreatePatternInput): Promise<ScamPatternRecord> {
    await this.initialize();

    const id = uuidv4();
    const status = input.status || 'active';

    const created = await prisma.scamPattern.create({
      data: {
        id,
        pattern: input.pattern,
        category: input.category,
        severity: input.severity,
        description: input.description,
        source: input.source,
        status,
      },
    });

    await this.refreshCache();

    return {
      ...created,
      severity: created.severity as PatternSeverity,
      status: created.status as PatternStatus,
      createdAt: created.createdAt.toISOString(),
      updatedAt: created.updatedAt.toISOString(),
    };
  }

  /**
   * Update an existing scam pattern. Automatically refreshes cache.
   */
  public async updatePattern(id: string, input: UpdatePatternInput): Promise<ScamPatternRecord | null> {
    await this.initialize();

    const existing = await prisma.scamPattern.findUnique({ where: { id } });
    if (!existing) {
      return null;
    }

    const updated = await prisma.scamPattern.update({
      where: { id },
      data: {
        pattern: input.pattern ?? undefined,
        category: input.category ?? undefined,
        severity: input.severity ?? undefined,
        description: input.description ?? undefined,
        source: input.source ?? undefined,
        status: input.status ?? undefined,
      },
    });

    await this.refreshCache();

    return {
      ...updated,
      severity: updated.severity as PatternSeverity,
      status: updated.status as PatternStatus,
      createdAt: updated.createdAt.toISOString(),
      updatedAt: updated.updatedAt.toISOString(),
    };
  }

  /**
   * Delete a scam pattern by ID. Automatically refreshes cache.
   */
  public async deletePattern(id: string): Promise<boolean> {
    await this.initialize();

    const existing = await prisma.scamPattern.findUnique({ where: { id } });
    if (!existing) {
      return false;
    }

    await prisma.scamPattern.delete({ where: { id } });
    await this.refreshCache();
    return true;
  }
}

export const scamIntelligenceService = ScamIntelligenceService.getInstance();
