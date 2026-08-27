import { hashingService } from '../../src/services/crypto/hashing.service';
import { canonicalizationService } from '../../src/services/crypto/canonicalization.service';
import { mockBlockchainRegistry } from '../../src/services/blockchain/blockchain-registry.mock';
import { NoticeCanonicalPayload } from '../../src/types';

describe('Sanity & Architecture Boundaries (Phase 1)', () => {
  beforeEach(() => {
    mockBlockchainRegistry.clear();
  });

  describe('Hashing Service Boundary', () => {
    it('should generate consistent SHA-256 hash', () => {
      const input = 'CLICKBAIT: Official Notice';
      const hash1 = hashingService.sha256(input);
      const hash2 = hashingService.sha256(input);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 hex string length
    });

    it('should verify matching hash with constant-time comparison', () => {
      const input = 'Sample text';
      const hash = hashingService.sha256(input);

      expect(hashingService.verifyHash(input, hash)).toBe(true);
      expect(hashingService.verifyHash('Tampered text', hash)).toBe(false);
    });
  });

  describe('Canonicalization Service Boundary', () => {
    it('should produce deterministic string for payload regardless of key order', () => {
      const payload1: NoticeCanonicalPayload = {
        institutionId: 'inst-123',
        title: 'Fee Payment Deadline',
        content: 'Exam fee deadline extended to March 31.',
        issuedAt: '2026-03-01T00:00:00.000Z',
        expiresAt: '2026-03-31T23:59:59.000Z',
      };

      const payload2: NoticeCanonicalPayload = {
        expiresAt: '2026-03-31T23:59:59.000Z',
        content: 'Exam fee deadline extended to March 31.',
        issuedAt: '2026-03-01T00:00:00.000Z',
        title: 'Fee Payment Deadline',
        institutionId: 'inst-123',
      };

      const canonical1 = canonicalizationService.canonicalize(payload1);
      const canonical2 = canonicalizationService.canonicalize(payload2);

      expect(canonical1).toBe(canonical2);
    });
  });

  describe('Blockchain Registry Interface & Privacy Compliance', () => {
    it('should record notice provenance on mock ledger without PII', async () => {
      const provenance = {
        institutionId: 'inst-univ-01',
        publicKeyRef: 'key-ref-ed25519-01',
        noticeId: 'notice-uuid-12345',
        contentHash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
        issuanceTimestamp: Math.floor(Date.now() / 1000),
        expiryTimestamp: Math.floor(Date.now() / 1000) + 86400,
        isRevoked: false,
      };

      const result = await mockBlockchainRegistry.registerNoticeProvenance(provenance);

      expect(result.success).toBe(true);
      expect(result.transactionHash).toMatch(/^0x[a-f0-9]{64}$/);

      const record = await mockBlockchainRegistry.getNoticeProvenance(provenance.noticeId);
      expect(record).not.toBeNull();
      expect(record?.noticeId).toBe(provenance.noticeId);
      expect(record?.isRevoked).toBe(false);

      // Verify that no PII fields exist in the blockchain payload contract
      expect((record as any).studentName).toBeUndefined();
      expect((record as any).studentEmail).toBeUndefined();
      expect((record as any).screenshot).toBeUndefined();
    });

    it('should update revocation status on ledger', async () => {
      const provenance = {
        institutionId: 'inst-univ-01',
        publicKeyRef: 'key-ref-ed25519-01',
        noticeId: 'notice-uuid-revoke-test',
        contentHash: 'hash1234567890',
        issuanceTimestamp: 1000,
        expiryTimestamp: 2000,
        isRevoked: false,
      };

      await mockBlockchainRegistry.registerNoticeProvenance(provenance);
      const revokeResult = await mockBlockchainRegistry.revokeNoticeProvenance(provenance.noticeId);

      expect(revokeResult.success).toBe(true);

      const updated = await mockBlockchainRegistry.getNoticeProvenance(provenance.noticeId);
      expect(updated?.isRevoked).toBe(true);
    });
  });
});
