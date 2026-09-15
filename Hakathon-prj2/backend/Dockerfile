# ==========================================
# Multi-Stage Production Dockerfile
# PinIt Security Backend & Antivirus Engine
# ==========================================

# 1. Base stage
FROM node:20-alpine AS base
WORKDIR /app
RUN apk add --no-cache libc6-compat openssl

# 2. Dependencies stage
FROM base AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
COPY prisma ./prisma
RUN npm ci

# 3. Builder stage
FROM dependencies AS builder
WORKDIR /app
COPY . .
RUN npm run build
RUN npm prune --production

# 4. Production Runner stage
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=4000
ENV HOST=0.0.0.0

# Create application user for least-privilege security
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 pinitsec -G nodejs

# Prepare safe storage directories with correct ownership
RUN mkdir -p /app/storage/temp /app/storage/quarantine /app/logs && \
    chown -R pinitsec:nodejs /app

# Copy production artifacts
COPY --from=builder --chown=pinitsec:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=pinitsec:nodejs /app/dist ./dist
COPY --from=builder --chown=pinitsec:nodejs /app/package.json ./package.json
COPY --from=builder --chown=pinitsec:nodejs /app/prisma ./prisma
COPY --from=builder --chown=pinitsec:nodejs /app/src/docs/openapi.yaml ./dist/docs/openapi.yaml

# Run as unprivileged user
USER pinitsec

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:4000/api/v1/health || exit 1

CMD ["node", "dist/server.js"]
