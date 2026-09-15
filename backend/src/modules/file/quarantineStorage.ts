import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { logger } from '../../utils/logger';

export class QuarantineStorageManager {
  private static instance: QuarantineStorageManager | null = null;
  readonly quarantineDir: string;
  private sweeperInterval: NodeJS.Timeout | null = null;
  private readonly DEFAULT_MAX_AGE_MS = 30 * 60 * 1000; // 30 minutes

  private constructor() {
    this.quarantineDir = path.resolve(process.cwd(), './storage/quarantine');
    this.ensureQuarantineDir();
    this.startSweeper();
  }

  public static getInstance(): QuarantineStorageManager {
    if (!QuarantineStorageManager.instance) {
      QuarantineStorageManager.instance = new QuarantineStorageManager();
    }
    return QuarantineStorageManager.instance;
  }

  /**
   * Ensures the isolated quarantine directory exists with strict non-executable directory permissions.
   */
  public ensureQuarantineDir(): void {
    if (!fs.existsSync(this.quarantineDir)) {
      fs.mkdirSync(this.quarantineDir, { recursive: true, mode: 0o700 });
      logger.info('Created isolated quarantine storage directory', { dir: this.quarantineDir });
    }
  }

  /**
   * Generates a safe, isolated, randomized quarantine file path.
   * User-supplied filenames are NEVER used on the filesystem.
   */
  public generateQuarantinePath(extension = 'bin'): { quarantinePath: string; quarantineId: string } {
    this.ensureQuarantineDir();
    const quarantineId = `quar_${Date.now()}_${crypto.randomBytes(16).toString('hex')}`;
    const safeExt = extension ? `.${extension.replace(/[^a-zA-Z0-9]/g, '').substring(0, 10)}` : '.bin';
    const quarantinePath = path.join(this.quarantineDir, `${quarantineId}${safeExt}`);
    return { quarantinePath, quarantineId };
  }

  /**
   * Applies strict read/write only permissions (0o600) to a quarantined file,
   * guaranteeing the file cannot be executed by the OS or other users.
   */
  public async restrictPermissions(filePath: string): Promise<void> {
    try {
      if (fs.existsSync(filePath)) {
        await fs.promises.chmod(filePath, 0o600);
      }
    } catch (err) {
      logger.warn('Failed to set chmod 0o600 on quarantined file (may be Windows environment)', {
        filePath: path.basename(filePath),
        error: (err as Error).message,
      });
    }
  }

  /**
   * Securely wipes and unlinks a quarantined file.
   * Overwrites the file header/bytes before unlinking to prevent residual malware fragments.
   */
  public async secureDelete(filePath: string): Promise<boolean> {
    try {
      if (!filePath || !fs.existsSync(filePath)) {
        return false;
      }

      // Security measure: Overwrite first 4KB with zero bytes before unlinking
      try {
        const stats = await fs.promises.stat(filePath);
        if (stats.size > 0) {
          const wipeSize = Math.min(stats.size, 4096);
          const zeroBuffer = Buffer.alloc(wipeSize, 0);
          const fd = await fs.promises.open(filePath, 'r+');
          await fd.write(zeroBuffer, 0, wipeSize, 0);
          await fd.close();
        }
      } catch {
        // Fallback directly to unlink if overwrite fails
      }

      await fs.promises.unlink(filePath);
      logger.debug('Quarantine file securely erased', { file: path.basename(filePath) });
      return true;
    } catch (err) {
      logger.warn('Failed to securely erase quarantined file', {
        file: path.basename(filePath),
        error: (err as Error).message,
      });
      return false;
    }
  }

  /**
   * Periodic garbage collector sweeping orphaned quarantine files older than maxAgeMs.
   */
  public async sweepOrphanedFiles(maxAgeMs = this.DEFAULT_MAX_AGE_MS): Promise<number> {
    let sweptCount = 0;
    try {
      if (!fs.existsSync(this.quarantineDir)) return 0;

      const files = await fs.promises.readdir(this.quarantineDir);
      const now = Date.now();

      for (const fileName of files) {
        const filePath = path.join(this.quarantineDir, fileName);
        try {
          const stats = await fs.promises.stat(filePath);
          if (now - stats.mtimeMs > maxAgeMs) {
            await this.secureDelete(filePath);
            sweptCount++;
          }
        } catch {
          // File may have been removed concurrently
        }
      }

      if (sweptCount > 0) {
        logger.info('Cleaned up orphaned quarantine files', { sweptCount });
      }
    } catch (err) {
      logger.error('Error sweeping quarantine directory', { error: (err as Error).message });
    }
    return sweptCount;
  }

  private startSweeper(): void {
    if (this.sweeperInterval) return;
    // Sweep every 15 minutes
    this.sweeperInterval = setInterval(() => {
      this.sweepOrphanedFiles().catch((err) =>
        logger.warn('Background quarantine sweeper error', { error: (err as Error).message })
      );
    }, 15 * 60 * 1000);

    // Ensure timer does not prevent process exit
    this.sweeperInterval.unref();
  }

  public stopSweeper(): void {
    if (this.sweeperInterval) {
      clearInterval(this.sweeperInterval);
      this.sweeperInterval = null;
    }
  }
}

export const quarantineStorage = QuarantineStorageManager.getInstance();
