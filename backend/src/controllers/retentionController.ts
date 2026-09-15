import { Request, Response, NextFunction } from 'express';
import { retentionWorker } from '../workers/retentionWorker';
import { config } from '../config';

export class RetentionController {
  async purgeExpiredData(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const days = req.query.days ? parseInt(req.query.days as string, 10) : config.dataRetentionDays;
      const result = await retentionWorker.purgeExpiredData(days);

      res.status(200).json({
        success: true,
        message: `Data retention purge executed successfully for records older than ${days} days.`,
        result,
      });
    } catch (err) {
      next(err);
    }
  }

  async getRetentionPolicy(_req: Request, res: Response): Promise<void> {
    res.status(200).json({
      success: true,
      retention_days: config.dataRetentionDays,
      policy: {
        api_usage_retention_days: config.dataRetentionDays,
        security_events_retention_days: config.dataRetentionDays,
        info_security_events_retention_days: 30,
        completed_scans_retention_days: config.dataRetentionDays,
      },
    });
  }
}

export const retentionController = new RetentionController();
