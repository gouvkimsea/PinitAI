import { Queue, Worker, Job } from 'bullmq';
import IORedis from 'ioredis';
import { scanService } from '../services/scanService';
import prisma from '../database/client';
import { config } from '../config';
import { logger } from '../utils/logger';
import { metricsCollector } from '../modules/monitoring/metricsCollector';

export interface FileScanJobData {
  type: 'FILE';
  scanId: string;
  tempFilePath: string;
  originalName: string;
  mimeType: string;
}

export interface UrlScanJobData {
  type: 'URL';
  scanId: string;
  url: string;
}

export interface TextScanJobData {
  type: 'TEXT';
  scanId: string;
  content: string;
  userId?: string | null;
}

export interface AiScanJobData {
  type: 'AI';
  scanId: string;
  data: any;
  userId?: string | null;
}

export type ScanJobData = FileScanJobData | UrlScanJobData | TextScanJobData | AiScanJobData;

/**
 * Abstract Scan Queue interface
 */
export interface IScanQueue {
  addJob(jobData: ScanJobData): Promise<void>;
  close(): Promise<void>;
}

/**
 * In-Memory Asynchronous Queue Fallback
 * Used for zero-dependency local development when Redis is not running.
 */
class InMemoryScanQueue implements IScanQueue {
  private queue: ScanJobData[] = [];
  private activeWorkers = 0;
  private readonly maxConcurrency = 5;

  async addJob(jobData: ScanJobData): Promise<void> {
    metricsCollector.recordQueueEnqueued();
    this.queue.push(jobData);
    logger.debug('Enqueued job in local async queue', {
      scanId: jobData.scanId,
      type: jobData.type,
      queueDepth: this.queue.length,
      activeWorkers: this.activeWorkers,
    });
    // Trigger queue processing across available concurrency slots
    this.spawnWorkers();
  }

  private spawnWorkers(): void {
    while (this.activeWorkers < this.maxConcurrency && this.queue.length > 0) {
      this.activeWorkers++;
      const job = this.queue.shift();
      if (!job) {
        this.activeWorkers--;
        break;
      }

      setImmediate(async () => {
        try {
          if (job.type === 'FILE') {
            await scanService.processFileScan(job.scanId, job.tempFilePath, job.originalName, job.mimeType);
          } else if (job.type === 'URL') {
            await scanService.processUrlScan(job.scanId, job.url);
          } else if (job.type === 'TEXT') {
            await scanService.processTextScan(job.scanId, job.content, job.userId);
          } else if (job.type === 'AI') {
            await scanService.processAiExplanationJob(job.scanId, job.data, job.userId);
          }
        } catch (err) {
          metricsCollector.recordQueueFailure();
          logger.trackQueueFailure({
            scanId: job.scanId,
            queueType: 'InMemory',
            error: (err as Error).message,
          });
          logger.error('Error processing in-memory scan job', { scanId: job.scanId, error: (err as Error).message });
          try {
            await prisma.scan.updateMany({
              where: { id: job.scanId },
              data: {
                status: 'FAILED',
                errorMessage: ((err as Error).message || 'In-memory processing failed').slice(0, 500),
              },
            });
          } catch (dbErr) {
            logger.error('Failed to update in-memory scan status to FAILED', { error: (dbErr as Error).message });
          }
        } finally {
          this.activeWorkers--;
          if (this.queue.length > 0) {
            this.spawnWorkers();
          }
        }
      });
    }
  }

  async close(): Promise<void> {
    this.queue = [];
  }
}

/**
 * BullMQ Redis Queue
 * Used in Docker / Production environments.
 */
class BullScanQueue implements IScanQueue {
  private queue: Queue<ScanJobData>;
  private worker: Worker<ScanJobData>;
  private connection: IORedis;

  constructor(redisUrl: string) {
    this.connection = new IORedis(redisUrl, { maxRetriesPerRequest: null });
    this.queue = new Queue('scan-jobs', { connection: this.connection });

    this.worker = new Worker(
      'scan-jobs',
      async (job: Job<ScanJobData>) => {
        const data = job.data;
        logger.info('Worker picked up job from BullMQ', { jobId: job.id, scanId: data.scanId });
        if (data.type === 'FILE') {
          await scanService.processFileScan(data.scanId, data.tempFilePath, data.originalName, data.mimeType);
        } else if (data.type === 'URL') {
          await scanService.processUrlScan(data.scanId, data.url);
        } else if (data.type === 'TEXT') {
          await scanService.processTextScan(data.scanId, data.content, data.userId);
        } else if (data.type === 'AI') {
          await scanService.processAiExplanationJob(data.scanId, data.data, data.userId);
        }
      },
      { connection: this.connection, concurrency: 5 }
    );

    this.worker.on('failed', async (job, err) => {
      metricsCollector.recordQueueFailure();
      logger.trackQueueFailure({
        scanId: job?.data?.scanId,
        jobId: job?.id,
        queueType: 'BullMQ',
        error: err.message,
        attemptsMade: job?.attemptsMade,
      });
      logger.error('BullMQ job failed', { jobId: job?.id, error: err.message });
      if (job && job.data?.scanId) {
        const maxAttempts = job.opts?.attempts || 1;
        if (job.attemptsMade >= maxAttempts) {
          try {
            await prisma.scan.updateMany({
              where: { id: job.data.scanId },
              data: {
                status: 'FAILED',
                errorMessage: (err.message || 'Job processing failed permanently').slice(0, 500),
              },
            });
            logger.warn('Scan marked as FAILED in database after retries exhausted', {
              scanId: job.data.scanId,
              attemptsMade: job.attemptsMade,
            });
          } catch (dbErr) {
            logger.error('Failed to update BullMQ scan status to FAILED in database', { error: (dbErr as Error).message });
          }
        }
      }
    });
  }

  async addJob(jobData: ScanJobData): Promise<void> {
    metricsCollector.recordQueueEnqueued();
    await this.queue.add(`scan-${jobData.type.toLowerCase()}`, jobData, {
      attempts: 2,
      backoff: { type: 'exponential', delay: 2000 },
      removeOnComplete: 100,
      removeOnFail: 500,
    });
  }

  async close(): Promise<void> {
    await this.worker.close();
    await this.queue.close();
    await this.connection.quit();
  }
}

// Instantiate Queue based on configuration
let scanQueueInstance: IScanQueue;

if (config.redisUrl && config.redisUrl.trim().length > 0) {
  try {
    scanQueueInstance = new BullScanQueue(config.redisUrl);
    logger.info('Initialized BullMQ Redis Scan Queue');
  } catch (err) {
    logger.warn('Failed to connect to Redis. Falling back to in-memory async queue', { error: (err as Error).message });
    scanQueueInstance = new InMemoryScanQueue();
  }
} else {
  logger.info('Using in-memory asynchronous scan queue for local execution');
  scanQueueInstance = new InMemoryScanQueue();
}

export const scanQueue = scanQueueInstance;
