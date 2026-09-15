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
    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS scam_patterns (
        id TEXT PRIMARY KEY,
        pattern TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        source TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        matchCount INTEGER NOT NULL DEFAULT 0,
        createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await prisma.$executeRawUnsafe(`
      CREATE INDEX IF NOT EXISTS idx_scam_patterns_category ON scam_patterns(category);
    `);
    await prisma.$executeRawUnsafe(`
      CREATE INDEX IF NOT EXISTS idx_scam_patterns_status ON scam_patterns(status);
    `);
    await prisma.$executeRawUnsafe(`
      CREATE INDEX IF NOT EXISTS idx_scam_patterns_severity ON scam_patterns(severity);
    `);
  }

  /**
   * Seeds the default catalog of 10 categories if table is currently empty.
   */
  public async seedDefaultCatalogIfEmpty(): Promise<number> {
    try {
      const countRows = await prisma.$queryRawUnsafe<Array<{ count: number | bigint }>>(
        `SELECT COUNT(*) as count FROM scam_patterns`
      );
      const total = Number(countRows[0]?.count || 0);

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
      await prisma.$executeRawUnsafe(`DELETE FROM scam_patterns`);
    }

    let inserted = 0;
    const now = new Date().toISOString();

    for (const item of DEFAULT_SCAM_PATTERNS) {
      const id = item.id || uuidv4();
      const status = item.status || 'active';

      try {
        if (forceReset) {
          await prisma.$executeRawUnsafe(
            `INSERT INTO scam_patterns (id, pattern, category, severity, description, source, status, createdAt, updatedAt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            id,
            item.pattern,
            item.category,
            item.severity,
            item.description,
            item.source,
            status,
            now,
            now
          );
          inserted++;
        } else {
          // Check if exists
          const existing = await prisma.$queryRawUnsafe<Array<{ id: string }>>(
            `SELECT id FROM scam_patterns WHERE pattern = ? LIMIT 1`,
            item.pattern
          );
          if (!existing || existing.length === 0) {
            await prisma.$executeRawUnsafe(
              `INSERT INTO scam_patterns (id, pattern, category, severity, description, source, status, createdAt, updatedAt)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              id,
              item.pattern,
              item.category,
              item.severity,
              item.description,
              item.source,
              status,
              now,
              now
            );
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
   * Refreshes the in-memory compiled regex cache from the SQLite database.
   */
  public async refreshCache(): Promise<void> {
    try {
      const rows = await prisma.$queryRawUnsafe<ScamPatternRecord[]>(
        `SELECT id, pattern, category, severity, description, source, status, createdAt, updatedAt
         FROM scam_patterns
         WHERE status = 'active'`
      );

      this.cache = this.compileRecords(rows);
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

    const conditions: string[] = ['1=1'];
    const params: unknown[] = [];

    if (filter?.category) {
      conditions.push('category = ?');
      params.push(filter.category);
    }
    if (filter?.severity) {
      conditions.push('severity = ?');
      params.push(filter.severity);
    }
    if (filter?.status) {
      conditions.push('status = ?');
      params.push(filter.status);
    }
    if (filter?.search) {
      conditions.push('(pattern LIKE ? OR description LIKE ? OR source LIKE ?)');
      const searchPattern = `%${filter.search}%`;
      params.push(searchPattern, searchPattern, searchPattern);
    }

    const whereClause = conditions.join(' AND ');
    const countSql = `SELECT COUNT(*) as count FROM scam_patterns WHERE ${whereClause}`;
    const countResult = await prisma.$queryRawUnsafe<Array<{ count: number | bigint }>>(countSql, ...params);
    const total = Number(countResult[0]?.count || 0);

    const limit = filter?.limit ? Math.max(1, Math.min(200, filter.limit)) : 50;
    const offset = filter?.offset ? Math.max(0, filter.offset) : 0;

    const dataSql = `
      SELECT id, pattern, category, severity, description, source, status, createdAt, updatedAt
      FROM scam_patterns
      WHERE ${whereClause}
      ORDER BY createdAt DESC
      LIMIT ? OFFSET ?
    `;

    const patterns = await prisma.$queryRawUnsafe<ScamPatternRecord[]>(dataSql, ...params, limit, offset);
    return { patterns, total };
  }

  /**
   * Get a single scam pattern by ID.
   */
  public async getPatternById(id: string): Promise<ScamPatternRecord | null> {
    await this.initialize();

    const rows = await prisma.$queryRawUnsafe<ScamPatternRecord[]>(
      `SELECT id, pattern, category, severity, description, source, status, createdAt, updatedAt
       FROM scam_patterns
       WHERE id = ?
       LIMIT 1`,
      id
    );

    return rows[0] || null;
  }

  /**
   * Create a new scam pattern. Automatically refreshes cache without restarting the app.
   */
  public async createPattern(input: CreatePatternInput): Promise<ScamPatternRecord> {
    await this.initialize();

    const id = uuidv4();
    const now = new Date().toISOString();
    const status = input.status || 'active';

    await prisma.$executeRawUnsafe(
      `INSERT INTO scam_patterns (id, pattern, category, severity, description, source, status, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id,
      input.pattern,
      input.category,
      input.severity,
      input.description,
      input.source,
      status,
      now,
      now
    );

    await this.refreshCache();

    const created = await this.getPatternById(id);
    if (!created) {
      throw new Error('Failed to retrieve newly created scam pattern.');
    }
    return created;
  }

  /**
   * Update an existing scam pattern. Automatically refreshes cache.
   */
  public async updatePattern(id: string, input: UpdatePatternInput): Promise<ScamPatternRecord | null> {
    await this.initialize();

    const existing = await this.getPatternById(id);
    if (!existing) {
      return null;
    }

    const updatedPattern = input.pattern ?? existing.pattern;
    const updatedCategory = input.category ?? existing.category;
    const updatedSeverity = input.severity ?? existing.severity;
    const updatedDescription = input.description ?? existing.description;
    const updatedSource = input.source ?? existing.source;
    const updatedStatus = input.status ?? existing.status;
    const now = new Date().toISOString();

    await prisma.$executeRawUnsafe(
      `UPDATE scam_patterns
       SET pattern = ?, category = ?, severity = ?, description = ?, source = ?, status = ?, updatedAt = ?
       WHERE id = ?`,
      updatedPattern,
      updatedCategory,
      updatedSeverity,
      updatedDescription,
      updatedSource,
      updatedStatus,
      now,
      id
    );

    await this.refreshCache();
    return this.getPatternById(id);
  }

  /**
   * Delete a scam pattern by ID. Automatically refreshes cache.
   */
  public async deletePattern(id: string): Promise<boolean> {
    await this.initialize();

    const existing = await this.getPatternById(id);
    if (!existing) {
      return false;
    }

    await prisma.$executeRawUnsafe(`DELETE FROM scam_patterns WHERE id = ?`, id);
    await this.refreshCache();
    return true;
  }
}

export const scamIntelligenceService = ScamIntelligenceService.getInstance();
