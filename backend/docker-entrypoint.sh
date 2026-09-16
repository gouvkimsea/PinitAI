#!/bin/sh
set -e

# Run Prisma migrations to ensure all database tables are up-to-date
if [ -n "$DATABASE_URL" ]; then
  echo "[entrypoint] Deploying database migrations..."
  npx prisma migrate deploy || echo "[entrypoint] Warning: prisma migrate deploy encountered an issue, proceeding..."
fi

# Hand over to server process
exec "$@"
