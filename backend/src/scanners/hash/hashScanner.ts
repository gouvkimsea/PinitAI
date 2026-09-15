import fs from 'fs';
import crypto from 'crypto';

export interface FileHashes {
  sha256: string;
  sha1: string;
  md5: string;
}

/**
 * Calculates SHA-256, SHA-1, and MD5 hashes simultaneously via streaming.
 */
export async function calculateFileHashes(filePath: string): Promise<FileHashes> {
  return new Promise((resolve, reject) => {
    const sha256 = crypto.createHash('sha256');
    const sha1 = crypto.createHash('sha1');
    const md5 = crypto.createHash('md5');

    const stream = fs.createReadStream(filePath);

    stream.on('data', (chunk) => {
      sha256.update(chunk);
      sha1.update(chunk);
      md5.update(chunk);
    });

    stream.on('end', () => {
      resolve({
        sha256: sha256.digest('hex'),
        sha1: sha1.digest('hex'),
        md5: md5.digest('hex'),
      });
    });

    stream.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Calculates hashes from an in-memory buffer.
 */
export function calculateBufferHashes(buffer: Buffer): FileHashes {
  return {
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
    sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
    md5: crypto.createHash('md5').update(buffer).digest('hex'),
  };
}
