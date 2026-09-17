#!/bin/sh
set -e

# Run Prisma schema push to ensure all database tables and relations exist in target database
if [ -n "$DATABASE_URL" ]; then
  if echo "$DATABASE_URL" | grep -qE "^(postgresql|postgres)://"; then
    echo "[entrypoint] Configuring Prisma datasource for PostgreSQL..."
    sed -i 's/provider = "sqlite"/provider = "postgresql"/' prisma/schema.prisma || true
    ./node_modules/.bin/prisma generate || npx prisma generate || true
  fi
  echo "[entrypoint] Synchronizing database schema with Prisma..."
  ./node_modules/.bin/prisma db push --skip-generate --accept-data-loss || \
  npx prisma db push --skip-generate --accept-data-loss || \
  ./node_modules/.bin/prisma migrate deploy || \
  npx prisma migrate deploy || \
  echo "[entrypoint] Warning: Prisma schema sync encountered an issue, proceeding..."
fi

# Hand over to server process
exec "$@"
