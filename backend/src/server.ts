import { createApp } from './app';
import { config } from './config';
import { logger } from './utils/logger';
import prisma from './database/client';
import { scanQueue } from './workers/scanQueue';
import { modelVersionService } from './modules/models/modelVersionService';
import { metricsCollector } from './modules/monitoring/metricsCollector';
import { retentionWorker } from './workers/retentionWorker';

const app = createApp();

const server = app.listen(config.port, () => {
  logger.info(`====================================================`);
  logger.info(`  PinIt Security & Antivirus Analysis Backend API   `);
  logger.info(`  Port:          ${config.port}`);
  logger.info(`  Environment:   ${config.nodeEnv}`);
  logger.info(`  API Docs:      http://localhost:${config.port}/api/docs`);
  logger.info(`  Health Probe:  http://localhost:${config.port}${config.apiPrefix}/health`);
  logger.info(`====================================================`);

  // Continuous health threshold monitoring & automated alerting
  metricsCollector.startHealthAlerts(60000);

  // Scheduled GDPR/PDPA data retention cleanup
  retentionWorker.startScheduledPurge();

  // Seed / sync model versions in background
  modelVersionService.seedDefaultModelVersions().catch((err) => {
    logger.warn('Initial model versions seed failed', { error: err.message });
  });
});

// Graceful Shutdown
const shutdown = async (signal: string) => {
  logger.info(`Received ${signal}. Gracefully shutting down security backend...`);
  metricsCollector.stopHealthAlerts();
  retentionWorker.stopScheduledPurge();

  server.close(async () => {
    try {
      await scanQueue.close();
      await prisma.$disconnect();
      logger.info('Database connections and queues closed. Exiting process.');
      process.exit(0);
    } catch (err) {
      logger.error('Error during shutdown', { error: (err as Error).message });
      process.exit(1);
    }
  });

  // Force shutdown after 10s if hanging
  setTimeout(() => {
    logger.error('Forceful shutdown triggered after timeout.');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
