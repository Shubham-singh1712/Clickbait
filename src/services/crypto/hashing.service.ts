import crypto from 'crypto';
import { canonicalizationService } from './canonicalization.service';
import { NoticeCanonicalPayload } from '../../types';

/**
 * Service interface for Cryptographic Hashing and Digest Verification.
 */
export interface IHashingService {
  sha256(data: string | Buffer): string;
  hashCanonicalPayload(payload: NoticeCanonicalPayload): string;
  verifyHash(dataOrHash: string | Buffer, expectedHashHex: string): boolean;
  verifyCanonicalPayloadHash(payload: NoticeCanonicalPayload, expectedHashHex: string): boolean;
}

export class HashingService implements IHashingService {
  /**
   * Generates a deterministic SHA-256 digest as a 64-character lowercase hexadecimal string.
   * Input strings are strictly encoded as UTF-8.
   */
  public sha256(data: string | Buffer): string {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf-8');
    return crypto.createHash('sha256').update(buffer).digest('hex').toLowerCase();
  }

  /**
   * Canonicalizes a notice payload using deterministic JSON canonicalization rules,
   * then computes the SHA-256 content hash.
   */
  public hashCanonicalPayload(payload: NoticeCanonicalPayload): string {
    const canonicalString = canonicalizationService.canonicalizeNoticePayload(payload);
    return this.sha256(canonicalString);
  }

  /**
   * Performs constant-time comparison between input data (or computed hash) and an expected SHA-256 hash.
   * Prevents timing attacks and verifies 64-character hex format validity.
   */
  public verifyHash(dataOrHash: string | Buffer, expectedHashHex: string): boolean {
    if (typeof expectedHashHex !== 'string') {
      return false;
    }

    const cleanExpected = expectedHashHex.trim().toLowerCase();

    // Verify expected hash is a valid 64-character hexadecimal string
    if (!/^[a-f0-9]{64}$/.test(cleanExpected)) {
      return false;
    }

    let computedHash: string;

    if (
      typeof dataOrHash === 'string' &&
      /^[a-f0-9]{64}$/i.test(dataOrHash.trim()) &&
      dataOrHash.trim().length === 64
    ) {
      // Direct hash comparison
      computedHash = dataOrHash.trim().toLowerCase();
    } else {
      // Compute hash of the raw string/buffer data
      computedHash = this.sha256(dataOrHash);
    }

    if (computedHash.length !== cleanExpected.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      Buffer.from(computedHash, 'hex'),
      Buffer.from(cleanExpected, 'hex')
    );
  }

  /**
   * Verifies that the computed SHA-256 hash of a canonical payload matches the expected hash.
   */
  public verifyCanonicalPayloadHash(
    payload: NoticeCanonicalPayload,
    expectedHashHex: string
  ): boolean {
    const computedHash = this.hashCanonicalPayload(payload);
    return this.verifyHash(computedHash, expectedHashHex);
  }
}

export const hashingService = new HashingService();
