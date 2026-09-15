import express, { Express, Request, Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import YAML from 'yaml';
import swaggerUi from 'swagger-ui-express';
import { config } from './config';
import { apiRouter } from './routes';
import { errorHandler } from './middleware/errorHandler';
import { auditLogger } from './middleware/auditLogger';
import { standardApiLimiter } from './middleware/rateLimiter';
import { requestTimeoutMiddleware } from './middleware/timeoutHandler';
import { requestIdMiddleware } from './middleware/requestId';
import { logger } from './utils/logger';

export function createApp(): Express {
  const app = express();

  // Enable trust proxy for accurate client IP identification behind load balancers/reverse proxies
  app.set('trust proxy', 1);

  // Request Tracing: assign unique request_id to every request
  app.use(requestIdMiddleware);

  // Circuit breaker: enforce request processing timeout limit
  app.use(requestTimeoutMiddleware(config.timeouts.requestTimeoutMs));

  // 1. Comprehensive Security Headers (Helmet)
  app.use(
    helmet({
      contentSecurityPolicy: false, // Permit Swagger UI styling
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'cross-origin' },
      dnsPrefetchControl: { allow: false },
      frameguard: { action: 'deny' }, // Prevent Clickjacking
      hidePoweredBy: true,
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
      },
      ieNoOpen: true,
      noSniff: true, // X-Content-Type-Options: nosniff
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      xssFilter: true,
    })
  );

  // 2. Hardened CORS Configuration
  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (e.g. mobile apps, curl, server-to-server)
        if (!origin) {
          return callback(null, true);
        }

        // In production, NEVER allow wildcard '*' when credentials are true
        if (config.isProduction && config.corsOrigins.includes('*')) {
          return callback(new Error('Insecure wildcard CORS origin prohibited in production environment.'));
        }

        if (config.corsOrigins.includes(origin) || (!config.isProduction && config.corsOrigins.includes('*'))) {
          callback(null, true);
        } else if (!config.isProduction) {
          // Allow standard localhost dev origins
          const isLocalhost = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
          if (isLocalhost) {
            callback(null, true);
          } else {
            callback(new Error(`Origin '${origin}' is not permitted by CORS policy in development.`));
          }
        } else {
          callback(new Error(`Origin '${origin}' is not permitted by CORS policy.`));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
      maxAge: 86400, // Preflight cache 24h
    })
  );

  // 3. Body Parsing with defensive size limits to prevent memory exhaustion DOS
  app.use(express.json({ limit: config.payloadLimits.maxJsonBodyBytes }));
  app.use(express.urlencoded({ extended: true, limit: config.payloadLimits.maxJsonBodyBytes }));

  // 4. Structured Audit Logging
  app.use(auditLogger);

  // 5. Global Rate Limiter
  app.use(standardApiLimiter);

  // 6. OpenAPI / Swagger Documentation
  try {
    const swaggerDocPath = path.resolve(__dirname, './docs/openapi.yaml');
    const fileContent = fs.readFileSync(swaggerDocPath, 'utf8');
    const swaggerDocument = YAML.parse(fileContent);
    app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
    logger.info('OpenAPI documentation initialized at /api/docs');
  } catch (err) {
    logger.warn('Failed to load Swagger documentation specification', { error: (err as Error).message });
  }

  // 7. Mount Primary API Router (Canonical /api and versioned /api/v1)
  app.use('/api', apiRouter);
  if (config.apiPrefix !== '/api') {
    app.use(config.apiPrefix, apiRouter);
  }

  // Support canonical root-level async analysis endpoint: POST /analyze, POST /analysis, and GET /analysis/:id
  app.post('/analyze', (req, res, next) => {
    req.url = '/analyze';
    apiRouter(req, res, next);
  });
  app.post('/analysis', (req, res, next) => {
    req.url = '/analyze';
    apiRouter(req, res, next);
  });
  app.get('/analysis/:id', (req, res, next) => {
    req.url = `/analysis/${req.params.id}`;
    apiRouter(req, res, next);
  });

  // Root-level health check aliases
  app.get('/health', (req, res, next) => {
    req.url = '/health';
    apiRouter(req, res, next);
  });
  app.get('/health/database', (req, res, next) => {
    req.url = '/health/database';
    apiRouter(req, res, next);
  });
  app.get('/health/services', (req, res, next) => {
    req.url = '/health/services';
    apiRouter(req, res, next);
  });
  app.get('/health/performance', (req, res, next) => {
    req.url = '/health/performance';
    apiRouter(req, res, next);
  });
  app.get('/metrics', (req, res, next) => {
    req.url = '/metrics';
    apiRouter(req, res, next);
  });

  // 8. Root Welcome & Discovery
  app.get('/', (_req: Request, res: Response) => {
    res.status(200).json({
      name: 'ScamCheck AI & Antivirus Detection API',
      version: '2.0.0',
      documentation: '/api/docs',
      health: '/api/health',
      health_database: '/api/health/database',
      health_services: '/api/health/services',
      endpoints: {
        async_analysis_job: '/analyze',
        async_job_status: '/api/analysis/:id',
        health: '/api/health',
        health_database: '/api/health/database',
        health_services: '/api/health/services',
        text_analysis: '/api/analyze/text',
        url_analysis: '/api/analyze/url',
        file_analysis: '/api/analyze/file',
        analysis_lookup: '/api/analysis/:id',
        community_reports: '/api/reports',
        feedback: '/api/feedback',
      },
    });
  });

  // 9. 404 Route Handler
  app.use((req: Request, res: Response) => {
    res.status(404).json({
      success: false,
      error: {
        code: 'ROUTE_NOT_FOUND',
        message: `Endpoint '${req.method} ${req.originalUrl}' does not exist. Refer to /api/docs for API specification.`,
      },
    });
  });

  // 10. Global Error Handler
  app.use(errorHandler);

  return app;
}

export default createApp;
