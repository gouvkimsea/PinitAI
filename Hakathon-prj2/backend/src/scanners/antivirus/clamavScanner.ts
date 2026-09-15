import net from 'net';
import fs from 'fs';
import { DetectionItem } from '../../types';
import { logger } from '../../utils/logger';
import { config } from '../../config';

export interface AntivirusScanResult {
  engine: 'ClamAV' | 'ClamAV-Simulated';
  isInfected: boolean;
  virusName?: string;
  isEngineReachable: boolean;
  detections: DetectionItem[];
}

// Standard EICAR test signature string (safe test pattern recognized by all standard AVs)
const EICAR_TEST_SIGNATURE = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

// Simulated known signatures for offline fallback verification
const FALLBACK_SIGNATURES: Array<{ signature: string | RegExp; virusName: string; category: string }> = [
  { signature: EICAR_TEST_SIGNATURE, virusName: 'Eicar-Test-Signature', category: 'antivirus_test' },
  { signature: /WanaCrypt0r|WANNACRY|@WanaDecryptor@/i, virusName: 'Ransom.WannaCry.Payload', category: 'ransomware' },
  { signature: /mimikatz|sekurlsa::logonpasswords/i, virusName: 'HackTool.Mimikatz.Gen', category: 'credential_theft' },
  { signature: /remcos_rat|darkcomet|njrat_stub/i, virusName: 'Trojan.RAT.Generic', category: 'remote_access_trojan' },
  { signature: /Invoke-Mimikatz|Invoke-ReflectivePEInjection/i, virusName: 'HackTool.PowerSploit', category: 'post_exploitation' },
];

/**
 * Scans a file with ClamAV daemon via TCP socket INSTREAM command.
 * If the ClamAV daemon is offline, falls back to a simulated signature engine
 * so developers and tests can verify full antivirus detection workflows without external blockers.
 */
export async function scanWithClamAV(filePath: string): Promise<AntivirusScanResult> {
  const detections: DetectionItem[] = [];

  try {
    const clamResult = await streamToClamAV(filePath, config.clamav.host, config.clamav.port, config.clamav.timeoutMs);
    if (clamResult.isInfected) {
      detections.push({
        engine: 'ClamAV',
        category: 'virus_detection',
        severity: 'critical',
        ruleId: 'CLAM-001',
        title: `Malware Detected by ClamAV: ${clamResult.virusName || 'Unknown Threat'}`,
        description: `ClamAV signature database matched a known malicious signature: ${clamResult.virusName}.`,
        details: { virusName: clamResult.virusName, engine: 'ClamAV' },
      });
    }

    return {
      engine: 'ClamAV',
      isInfected: clamResult.isInfected,
      virusName: clamResult.virusName,
      isEngineReachable: true,
      detections,
    };
  } catch (err) {
    logger.debug('ClamAV daemon not reachable or timed out. Falling back to built-in signature engine.', {
      host: config.clamav.host,
      port: config.clamav.port,
      error: (err as Error).message,
    });

    // Fallback signature scan
    const fallbackResult = await scanWithFallbackSignatures(filePath);
    if (fallbackResult.isInfected) {
      detections.push({
        engine: 'ClamAV-Simulated',
        category: 'virus_detection',
        severity: 'critical',
        ruleId: 'CLAM-SIM-001',
        title: `Threat Signature Detected: ${fallbackResult.virusName}`,
        description: `Built-in antivirus signature matched known malicious test pattern: ${fallbackResult.virusName}.`,
        details: { virusName: fallbackResult.virusName, simulated: true },
      });
    }

    return {
      engine: 'ClamAV-Simulated',
      isInfected: fallbackResult.isInfected,
      virusName: fallbackResult.virusName,
      isEngineReachable: false,
      detections,
    };
  }
}

/**
 * Streams file to ClamAV daemon using zINSTREAM command over TCP.
 */
function streamToClamAV(
  filePath: string,
  host: string,
  port: number,
  timeoutMs: number
): Promise<{ isInfected: boolean; virusName?: string }> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let response = '';

    socket.setTimeout(timeoutMs);

    socket.connect(port, host, () => {
      // Send zINSTREAM (null-terminated prefix command)
      socket.write('zINSTREAM\0');

      const readStream = fs.createReadStream(filePath, { highWaterMark: 64 * 1024 });

      readStream.on('data', (chunk: string | Buffer) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const lengthBuffer = Buffer.alloc(4);
        lengthBuffer.writeUInt32BE(buf.length, 0);
        socket.write(lengthBuffer);
        socket.write(buf);
      });

      readStream.on('end', () => {
        // Zero-length chunk marks end of stream
        const zeroChunk = Buffer.alloc(4);
        zeroChunk.writeUInt32BE(0, 0);
        socket.write(zeroChunk);
      });

      readStream.on('error', (err) => {
        socket.destroy();
        reject(err);
      });
    });

    socket.on('data', (data) => {
      response += data.toString('utf8');
    });

    socket.on('end', () => {
      response = response.trim();
      if (response.includes('FOUND')) {
        // e.g. "stream: Win.Trojan.Agent-1234 FOUND"
        const match = response.match(/stream:\s*(.+?)\s+FOUND/i);
        const virusName = match ? match[1] : 'Malware.Detected';
        resolve({ isInfected: true, virusName });
      } else if (response.includes('OK')) {
        resolve({ isInfected: false });
      } else {
        reject(new Error(`Unexpected ClamAV response: ${response}`));
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`ClamAV socket timeout after ${timeoutMs}ms`));
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });
  });
}

/**
 * Scans file contents against known test signatures for fallback local testing.
 */
async function scanWithFallbackSignatures(filePath: string): Promise<{ isInfected: boolean; virusName?: string }> {
  try {
    const buffer = await fs.promises.readFile(filePath);
    const content = buffer.toString('utf8');

    for (const item of FALLBACK_SIGNATURES) {
      if (typeof item.signature === 'string') {
        if (content.includes(item.signature)) {
          return { isInfected: true, virusName: item.virusName };
        }
      } else if (item.signature.test(content)) {
        return { isInfected: true, virusName: item.virusName };
      }
    }

    return { isInfected: false };
  } catch (err) {
    logger.warn('Failed to read file for fallback signature scan', { error: (err as Error).message });
    return { isInfected: false };
  }
}
