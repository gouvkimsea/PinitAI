import { describe, it, expect } from 'vitest';
import { calculateBufferHashes } from '../src/scanners/hash/hashScanner';

describe('Hash Scanner', () => {
  it('should accurately calculate sha256, sha1, and md5 hashes for known strings', () => {
    // Hashes for string "Hello PinIt Security"
    const buffer = Buffer.from('Hello PinIt Security', 'utf8');
    const hashes = calculateBufferHashes(buffer);

    expect(hashes.sha256).toBe('9e0e292ed910b40ff948e21cf20ce02ab3f04394d2c215c0d5f606094b5f29dc');
    expect(hashes.sha1).toBe('5176bfc7edccec4f794c0c89798b430be50069bc');
    expect(hashes.md5).toBe('b9deaac01cd823d775a61322891f2920');
  });

  it('should correctly calculate the official EICAR test file hash', () => {
    const eicar = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', 'utf8');
    const hashes = calculateBufferHashes(eicar);

    // Standard EICAR SHA-256
    expect(hashes.sha256).toBe('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
    expect(hashes.md5).toBe('44d88612fea8a8f36de82e1278abb02f');
  });
});
