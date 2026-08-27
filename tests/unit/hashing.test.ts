import { hashingService } from '../../src/services/crypto/hashing.service';
import { NoticeCanonicalPayload } from '../../src/types';

describe('Phase 2 — SHA-256 Hashing Service Tests', () => {
  // TEST 6 — SHA-256 known test vectors (NIST / standard standard test vectors)
  describe('Standard Test Vectors', () => {
    it('TEST 6.1: should match known SHA-256 hash of empty string', () => {
      // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const hash = hashingService.sha256('');
      expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('TEST 6.2: should match known SHA-256 hash of "The quick brown fox jumps over the lazy dog"', () => {
      const input = 'The quick brown fox jumps over the lazy dog';
      const expected = 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592';
      const hash = hashingService.sha256(input);
      expect(hash).toBe(expected);
    });

    it('TEST 6.3: should correctly hash UTF-8 Unicode characters (multi-byte sequences)', () => {
      // UTF-8 test string with multilingual characters and symbols
      const input = 'CLICKBAIT 🏛️ 🔒 — भारत (India) ₹1000';
      const hash1 = hashingService.sha256(input);
      const hash2 = hashingService.sha256(input);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  // TEST 5 — Different content
  describe('Content Integrity & Avalanche Effect', () => {
    it('TEST 5: should generate entirely different SHA-256 hash when single character changes', () => {
      const notice1: NoticeCanonicalPayload = {
        institutionId: 'inst-01',
        title: 'Fee Payment Circular',
        content: 'Deadline is April 10, 2026.',
        issuedAt: '2026-04-01T00:00:00.000Z',
        expiresAt: '2026-04-10T23:59:59.000Z',
      };

      const notice2: NoticeCanonicalPayload = {
        institutionId: 'inst-01',
        title: 'Fee Payment Circular',
        content: 'Deadline is April 11, 2026.', // Changed single character 0 -> 1
        issuedAt: '2026-04-01T00:00:00.000Z',
        expiresAt: '2026-04-10T23:59:59.000Z',
      };

      const hash1 = hashingService.hashCanonicalPayload(notice1);
      const hash2 = hashingService.hashCanonicalPayload(notice2);

      expect(hash1).not.toBe(hash2);
      expect(hash1).toHaveLength(64);
      expect(hash2).toHaveLength(64);
    });
  });

  // TEST 7 — Hash verification
  describe('Hash Verification & Constant-Time Security', () => {
    it('TEST 7.1: should return true when calculated hash matches expected hash', () => {
      const data = 'CLICKBAIT Official Notice Test Payload';
      const expectedHash = hashingService.sha256(data);

      expect(hashingService.verifyHash(data, expectedHash)).toBe(true);
      expect(hashingService.verifyHash(Buffer.from(data, 'utf-8'), expectedHash)).toBe(true);
    });

    it('TEST 7.2: should return false when data has been tampered with', () => {
      const original = 'Authentic Circular Content';
      const tampered = 'Tampered Circular Content';
      const expectedHash = hashingService.sha256(original);

      expect(hashingService.verifyHash(tampered, expectedHash)).toBe(false);
    });

    it('TEST 7.3: should return false for malformed or non-64-char expected hashes', () => {
      const data = 'Some data';
      expect(hashingService.verifyHash(data, 'invalid-short-hash')).toBe(false);
      expect(hashingService.verifyHash(data, 'not-a-hex-string-at-all-xyz1234567890123456789012345678901234567890')).toBe(false);
      expect(hashingService.verifyHash(data, '' as any)).toBe(false);
      expect(hashingService.verifyHash(data, null as any)).toBe(false);
    });

    it('TEST 7.4: should verify canonical notice payload hash accurately', () => {
      const notice: NoticeCanonicalPayload = {
        institutionId: 'inst-univ-01',
        title: 'Holiday Circular',
        content: 'Campus closed on Friday.',
        issuedAt: '2026-05-01T00:00:00.000Z',
        expiresAt: '2026-05-02T23:59:59.000Z',
      };

      const computedHash = hashingService.hashCanonicalPayload(notice);
      expect(hashingService.verifyCanonicalPayloadHash(notice, computedHash)).toBe(true);

      const tamperedNotice = { ...notice, title: 'Fake Holiday Circular' };
      expect(hashingService.verifyCanonicalPayloadHash(tamperedNotice, computedHash)).toBe(false);
    });
  });
});
