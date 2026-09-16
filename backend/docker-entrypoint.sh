#!/bin/sh
set -e

# Run Prisma schema push to ensure all database tables and relations exist in PostgreSQL
if [ -n "$DATABASE_URL" ]; then
  echo "[entrypoint] Synchronizing PostgreSQL schema with Prisma..."
  ./node_modules/.bin/prisma db push --skip-generate --accept-data-loss || \
  npx prisma db push --skip-generate --accept-data-loss || \
  ./node_modules/.bin/prisma migrate deploy || \
  npx prisma migrate deploy || \
  echo "[entrypoint] Warning: Prisma schema sync encountered an issue, proceeding..."
fi

# Hand over to server process
exec "$@"
