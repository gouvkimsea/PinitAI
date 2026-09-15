import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';
import { MetricsCollector } from '../modules/monitoring/metricsCollector';

declare global {
  // eslint-disable-next-line no-var
  var prismaInstance: PrismaClient | undefined;
}

const basePrisma =
  global.prismaInstance ||
  new PrismaClient({
    log: [
      { emit: 'event', level: 'error' },
      { emit: 'event', level: 'warn' },
    ],
  });

basePrisma.$on('error' as never, (e: any) => {
  const errorMsg = e?.message || String(e);
  logger.trackDatabaseError({
    operation: e?.target || 'query',
    error: errorMsg,
    target: e?.target,
  });
});

basePrisma.$on('warn' as never, (e: any) => {
  logger.warn('Database warning encountered', {
    event_type: 'DATABASE_WARNING',
    warning: e?.message || String(e),
  });
});

// Record query execution time for performance metrics using Prisma 6 $extends
export const prisma = (basePrisma as any).$extends({
  query: {
    $allModels: {
      async $allOperations({ query, args }: { query: any; args: any }) {
        const start = performance.now();
        const result = await query(args);
        const duration = performance.now() - start;
        MetricsCollector.getInstance().recordDbQuery(duration);
        return result;
      },
    },
  },
}) as PrismaClient;

/**
 * Configure SQLite high-concurrency PRAGMAs (WAL mode, busy timeout, memory cache)
 * Safely bypassed when running on PostgreSQL or other relational providers.
 */
export async function initializeDatabasePragmas(): Promise<void> {
  const isPostgres = (process.env.DATABASE_URL || '').startsWith('postgres') || process.env.DATABASE_PROVIDER === 'postgresql';
  if (isPostgres) {
    logger.info('Database provider is PostgreSQL; SQLite PRAGMAs safely bypassed');
    return;
  }

  try {
    await prisma.$queryRawUnsafe('PRAGMA journal_mode = WAL;');
    await prisma.$queryRawUnsafe('PRAGMA synchronous = NORMAL;');
    await prisma.$queryRawUnsafe('PRAGMA cache_size = 10000;');
    await prisma.$queryRawUnsafe('PRAGMA busy_timeout = 5000;');
    await prisma.$queryRawUnsafe('PRAGMA temp_store = MEMORY;');
    logger.info('Database SQLite performance PRAGMAs initialized (WAL mode, cache, busy timeout active)');
  } catch (err: any) {
    logger.warn('Failed to apply SQLite performance PRAGMAs', { error: err?.message });
  }
}

// Automatically apply pragmas on initial load
initializeDatabasePragmas().catch(() => {});

if (process.env.NODE_ENV !== 'production') {
  global.prismaInstance = prisma;
}

export default prisma;

