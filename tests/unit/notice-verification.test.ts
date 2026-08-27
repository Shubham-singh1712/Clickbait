import { VerificationService } from '../../src/services/verification/verification.service';
import { IssuerRegistryService } from '../../src/services/registry/issuer-registry.service';
import { NoticeService, NoticeRecord } from '../../src/services/notice/notice.service';
import { ed25519Service } from '../../src/services/crypto/ed25519.service';
import { canonicalizationService } from '../../src/services/crypto/canonicalization.service';
import { hashingService } from '../../src/services/crypto/hashing.service';
import {
  InstitutionRecord,
  IssuerKeyRecord,
  NoticeCanonicalPayload,
  KeyStatus,
} from '../../src/types';
import { PrismaClient } from '@prisma/client';

/**
 * In-memory Mock Prisma Client for hermetic testing of VerificationService.
 */
class InMemoryVerificationPrismaMock {
  public institutions: Map<string, InstitutionRecord> = new Map();
  public keys: Map<string, IssuerKeyRecord> = new Map();
  public notices: Map<string, NoticeRecord> = new Map();

  public institution = {
    findUnique: jest.fn(async ({ where }: { where: { id?: string; verifiedDomain?: string } }) => {
      if (where.id) return this.institutions.get(where.id) || null;
      if (where.verifiedDomain) {
        for (const inst of this.institutions.values()) {
          if (inst.verifiedDomain === where.verifiedDomain) return inst;
        }
      }
      return null;
    }),
  };

  public issuerKey = {
    findUnique: jest.fn(async ({ where }: { where: { id?: string; publicKey?: string } }) => {
      if (where.id) return this.keys.get(where.id) || null;
      if (where.publicKey) {
        for (const key of this.keys.values()) {
          if (key.publicKey === where.publicKey) return key;
        }
      }
      return null;
    }),

    findFirst: jest.fn(
      async ({
        where,
      }: {
        where: {
          institutionId: string;
          keyStatus?: KeyStatus;
          expiresAt?: { gt: Date };
          revokedAt?: null;
        };
      }) => {
        const now = new Date();
        const matches: IssuerKeyRecord[] = [];
        for (const key of this.keys.values()) {
          if (key.institutionId !== where.institutionId) continue;
          if (where.keyStatus && key.keyStatus !== where.keyStatus) continue;
          if (where.revokedAt === null && key.revokedAt !== null && key.revokedAt !== undefined) continue;
          if (where.expiresAt && key.expiresAt <= now) continue;
          matches.push(key);
        }
        matches.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
        return matches.length > 0 ? matches[0] : null;
      }
    ),
  };

  public notice = {
    create: jest.fn(async ({ data }: { data: any }) => {
      const id = data.id || `notice-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      const record: NoticeRecord = {
        id,
        institutionId: data.institutionId,
        title: data.title,
        contentHash: data.contentHash,
        signature: data.signature,
        issuedAt: new Date(data.issuedAt),
        expiresAt: new Date(data.expiresAt),
        status: data.status || 'ACTIVE',
        revocationReason: null,
        revokedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      this.notices.set(id, record);
      return record;
    }),

    findUnique: jest.fn(async ({ where }: { where: { id: string } }) => {
      return this.notices.get(where.id) || null;
    }),
  };

  public reset(): void {
    this.institutions.clear();
    this.keys.clear();
    this.notices.clear();
    jest.clearAllMocks();
  }
}

describe('Phase 6 — Public Notice Verification Service Tests', () => {
  let mockPrisma: InMemoryVerificationPrismaMock;
  let registryService: IssuerRegistryService;
  let noticeService: NoticeService;
  let verificationService: VerificationService;
  let sampleInstitution: InstitutionRecord;
  let institutionKeyPair: { publicKeyBase64: string; privateKeyBase64: string };
  const futureExpiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year in future

  beforeEach(() => {
    mockPrisma = new InMemoryVerificationPrismaMock();
    registryService = new IssuerRegistryService(mockPrisma as unknown as PrismaClient);
    noticeService = new NoticeService(mockPrisma as unknown as PrismaClient, registryService);
    verificationService = new VerificationService(
      mockPrisma as unknown as PrismaClient,
      registryService,
      canonicalizationService,
      hashingService,
      ed25519Service
    );

    // Setup active registered institution
    sampleInstitution = {
      id: 'inst-delhi-university-01',
      name: 'University of Delhi',
      verifiedDomain: 'du.ac.in',
      status: 'ACTIVE',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    mockPrisma.institutions.set(sampleInstitution.id, sampleInstitution);

    // Setup registered Ed25519 public key
    institutionKeyPair = ed25519Service.generateKeyPair();
    const keyRecord: IssuerKeyRecord = {
      id: 'key-du-active-01',
      institutionId: sampleInstitution.id,
      publicKey: institutionKeyPair.publicKeyBase64,
      keyStatus: 'ACTIVE',
      createdAt: new Date(),
      expiresAt: futureExpiry,
      revokedAt: null,
    };
    mockPrisma.keys.set(keyRecord.id, keyRecord);

    noticeService.setInstitutionSigningKey(sampleInstitution.id, institutionKeyPair.privateKeyBase64);
  });

  // TEST 1 — Valid notice verification
  it('TEST 1: should verify a legitimate signed notice successfully (isAuthentic = true)', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Official Academic Calendar 2026',
      content: 'Classes commence on August 1, 2026.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
      metadata: { semester: 'Autumn', batch: 2026 },
    });

    const result = await verificationService.verifyNotice({
      payload: {
        noticeId: signedNotice.noticeId,
        institutionId: signedNotice.institutionId,
        title: signedNotice.title,
        content: signedNotice.content,
        issuedAt: signedNotice.issuedAt,
        expiresAt: signedNotice.expiresAt,
        metadata: signedNotice.metadata,
      },
      signature: signedNotice.signature,
      contentHash: signedNotice.contentHash,
    });

    expect(result.isAuthentic).toBe(true);
    expect(result.resultStatus).toBe('VERIFIED');
    expect(result.riskLevel).toBe('NONE');
    expect(result.checks.signatureValid).toBe(true);
    expect(result.checks.integrityVerified).toBe(true);
    expect(result.checks.notExpired).toBe(true);
    expect(result.checks.notRevoked).toBe(true);
    expect(result.checks.trustedIssuerKey).toBe(true);
    expect(result.institution?.name).toBe('University of Delhi');
  });

  // TEST 2 — Tampered content detection
  it('TEST 2: should fail verification when notice content has been tampered with', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Fee Payment Circular',
      content: 'Tuition fee is Rs 5,000.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    const result = await verificationService.verifyNotice({
      payload: {
        noticeId: signedNotice.noticeId,
        institutionId: signedNotice.institutionId,
        title: signedNotice.title,
        content: 'Tampered: Tuition fee is Rs 50,000.', // Forged content
        issuedAt: signedNotice.issuedAt,
        expiresAt: signedNotice.expiresAt,
      },
      signature: signedNotice.signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.resultStatus).toBe('TAMPERED');
    expect(result.riskLevel).toBe('CRITICAL');
    expect(result.checks.signatureValid).toBe(false);
  });

  // TEST 3 — Tampered title detection
  it('TEST 3: should fail verification when notice title has been altered', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Holiday Notice',
      content: 'Campus closed on Friday.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    const result = await verificationService.verifyNotice({
      payload: {
        noticeId: signedNotice.noticeId,
        institutionId: signedNotice.institutionId,
        title: 'Forged Title: Exam Cancelled',
        content: signedNotice.content,
        issuedAt: signedNotice.issuedAt,
        expiresAt: signedNotice.expiresAt,
      },
      signature: signedNotice.signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.resultStatus).toBe('TAMPERED');
    expect(result.checks.signatureValid).toBe(false);
  });

  // TEST 4 — Tampered metadata detection
  it('TEST 4: should fail verification when signed metadata has been altered', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Hostel Allotment List',
      content: 'List of allotted candidates.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
      metadata: { quota: 'General', feePaid: true },
    });

    const result = await verificationService.verifyNotice({
      payload: {
        noticeId: signedNotice.noticeId,
        institutionId: signedNotice.institutionId,
        title: signedNotice.title,
        content: signedNotice.content,
        issuedAt: signedNotice.issuedAt,
        expiresAt: signedNotice.expiresAt,
        metadata: { quota: 'Management', feePaid: false }, // Tampered metadata
      },
      signature: signedNotice.signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.resultStatus).toBe('TAMPERED');
    expect(result.checks.signatureValid).toBe(false);
  });

  // TEST 5 — Tampered issuedAt timestamp detection
  it('TEST 5: should fail verification when issuedAt timestamp has been modified', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Admission List',
      content: 'Merit list published.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    const result = await verificationService.verifyNotice({
      payload: {
        noticeId: signedNotice.noticeId,
        institutionId: signedNotice.institutionId,
        title: signedNotice.title,
        content: signedNotice.content,
        issuedAt: '2026-07-15T00:00:00.000Z', // Tampered date
        expiresAt: signedNotice.expiresAt,
      },
      signature: signedNotice.signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.resultStatus).toBe('TAMPERED');
    expect(result.checks.signatureValid).toBe(false);
  });

  // TEST 6 — Tampered expiresAt timestamp detection
  it('TEST 6: should fail verification when expiresAt timestamp has been extended', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Tender Application Deadline',
      content: 'Submit bids before deadline.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-08-31T23:59:59.000Z',
    });

    const result = await verificationService.verifyNotice({
      payload: {
        noticeId: signedNotice.noticeId,
        institutionId: signedNotice.institutionId,
        title: signedNotice.title,
        content: signedNotice.content,
        issuedAt: signedNotice.issuedAt,
        expiresAt: '2026-12-31T23:59:59.000Z', // Forged extended deadline
      },
      signature: signedNotice.signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.resultStatus).toBe('TAMPERED');
    expect(result.checks.signatureValid).toBe(false);
  });

  // TEST 7 — Expired notice detection
  it('TEST 7: should detect expired notices and mark notExpired = false', async () => {
    // Generate valid signed notice whose expiry is in the past
    const expiredPayload: NoticeCanonicalPayload = {
      institutionId: sampleInstitution.id,
      title: 'Past Notice Event',
      content: 'This notice expired yesterday.',
      issuedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(), // 10 days ago
      expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // 1 day ago
    };

    const canonicalStr = canonicalizationService.canonicalizeNoticePayload(expiredPayload);
    const signature = ed25519Service.sign(canonicalStr, institutionKeyPair.privateKeyBase64);

    const result = await verificationService.verifyNotice({
      payload: expiredPayload,
      signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.resultStatus).toBe('EXPIRED');
    expect(result.checks.notExpired).toBe(false);
    expect(result.checks.signatureValid).toBe(true);
    expect(result.checks.trustedIssuerKey).toBe(true);
  });

  // TEST 8 — Unknown institution rejection
  it('TEST 8: should reject verification when institution is not registered in the registry', async () => {
    const unknownInstId = 'inst-unknown-random-999';
    const arbitraryKey = ed25519Service.generateKeyPair();

    const payload: NoticeCanonicalPayload = {
      institutionId: unknownInstId,
      title: 'Unauthorized Circular',
      content: 'Content from unknown source.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    };

    const canonicalStr = canonicalizationService.canonicalizeNoticePayload(payload);
    const signature = ed25519Service.sign(canonicalStr, arbitraryKey.privateKeyBase64);

    const result = await verificationService.verifyNotice({
      payload,
      signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.resultStatus).toBe('UNVERIFIED');
    expect(result.checks.trustedIssuerKey).toBe(false);
  });

  // TEST 9 — Suspended institution rejection
  it('TEST 9: should reject verification for suspended institutions', async () => {
    const suspendedInst: InstitutionRecord = {
      id: 'inst-suspended-board-02',
      name: 'Suspended Education Board',
      verifiedDomain: 'suspended-board.edu',
      status: 'SUSPENDED',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    mockPrisma.institutions.set(suspendedInst.id, suspendedInst);

    const suspendedKey = ed25519Service.generateKeyPair();
    const payload: NoticeCanonicalPayload = {
      institutionId: suspendedInst.id,
      title: 'Board Exam Schedule',
      content: 'Official exam schedule.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    };

    const canonicalStr = canonicalizationService.canonicalizeNoticePayload(payload);
    const signature = ed25519Service.sign(canonicalStr, suspendedKey.privateKeyBase64);

    const result = await verificationService.verifyNotice({
      payload,
      signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.resultStatus).toBe('UNVERIFIED');
    expect(result.checks.trustedIssuerKey).toBe(false);
  });

  // TEST 10 — Revoked issuer key rejection
  it('TEST 10: should reject verification when institution public key has been revoked', async () => {
    // 1. Notice was legitimately signed while key was active
    const payload: NoticeCanonicalPayload = {
      institutionId: sampleInstitution.id,
      title: 'Old Notice',
      content: 'Content from old key.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    };
    const canonicalStr = canonicalizationService.canonicalizeNoticePayload(payload);
    const signature = ed25519Service.sign(canonicalStr, institutionKeyPair.privateKeyBase64);

    // 2. Later, key is revoked in the registry
    const key = mockPrisma.keys.get('key-du-active-01')!;
    key.keyStatus = 'REVOKED';
    key.revokedAt = new Date();

    // 3. Verification must fail because issuer key is no longer trusted/active
    const result = await verificationService.verifyNotice({
      payload,
      signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.checks.trustedIssuerKey).toBe(false);
  });

  // TEST 11 — Expired issuer key rejection
  it('TEST 11: should reject verification when institution public key is expired', async () => {
    // 1. Notice was legitimately signed while key was active
    const payload: NoticeCanonicalPayload = {
      institutionId: sampleInstitution.id,
      title: 'Expired Key Circular',
      content: 'Key has elapsed.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    };
    const canonicalStr = canonicalizationService.canonicalizeNoticePayload(payload);
    const signature = ed25519Service.sign(canonicalStr, institutionKeyPair.privateKeyBase64);

    // 2. Later, key expires in the registry
    const key = mockPrisma.keys.get('key-du-active-01')!;
    key.expiresAt = new Date(Date.now() - 1000); // Expired 1 second ago

    // 3. Verification must fail because issuer key has expired
    const result = await verificationService.verifyNotice({
      payload,
      signature,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.checks.trustedIssuerKey).toBe(false);
  });

  // TEST 12 — Arbitrary client public key not trusted
  it('TEST 12: should verify against registry key only, ignoring any client-supplied public key', async () => {
    // Attacker signs payload with their own key
    const attackerKey = ed25519Service.generateKeyPair();
    const payload: NoticeCanonicalPayload = {
      institutionId: sampleInstitution.id,
      title: 'Forged Notice',
      content: 'Attacker signed content claiming to be University of Delhi.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    };

    const canonicalStr = canonicalizationService.canonicalizeNoticePayload(payload);
    const attackerSignature = ed25519Service.sign(canonicalStr, attackerKey.privateKeyBase64);

    // Client passes attacker's public key in request
    const result = await verificationService.verifyNotice({
      payload,
      signature: attackerSignature,
      publicKey: attackerKey.publicKeyBase64, // Attacker attempts key override
    });

    // Verification must FAIL because the registry key does not verify attacker's signature
    expect(result.isAuthentic).toBe(false);
    expect(result.resultStatus).toBe('TAMPERED');
    expect(result.checks.signatureValid).toBe(false);
  });

  // TEST 13 — Invalid signature format rejection
  it('TEST 13: should safely handle malformed signature strings without throwing unexpected crashes', async () => {
    const payload: NoticeCanonicalPayload = {
      institutionId: sampleInstitution.id,
      title: 'Valid Notice Title',
      content: 'Valid content.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    };

    const malformedSignatures = [
      'not-a-valid-base64!@#$',
      '???invalid???',
      Buffer.alloc(32, 0xaa).toString('base64'), // 32 bytes instead of 64 bytes
      Buffer.alloc(128, 0xbb).toString('base64'), // 128 bytes instead of 64 bytes
    ];

    for (const badSig of malformedSignatures) {
      const result = await verificationService.verifyNotice({
        payload,
        signature: badSig,
      });

      expect(result.isAuthentic).toBe(false);
      expect(result.checks.signatureValid).toBe(false);
    }
  });

  // TEST 14 — Missing required fields rejection
  it('TEST 14: should reject verification request with missing required payload fields', async () => {
    // Missing title
    await expect(
      verificationService.verifyNotice({
        payload: {
          institutionId: sampleInstitution.id,
          title: '',
          content: 'Some content',
          issuedAt: '2026-07-01T00:00:00.000Z',
          expiresAt: '2026-12-31T23:59:59.000Z',
        },
        signature: 'dummy_sig',
      })
    ).rejects.toThrow(/title/);

    // Missing institutionId
    await expect(
      verificationService.verifyNotice({
        payload: {
          institutionId: '   ',
          title: 'Valid Title',
          content: 'Some content',
          issuedAt: '2026-07-01T00:00:00.000Z',
          expiresAt: '2026-12-31T23:59:59.000Z',
        },
        signature: 'dummy_sig',
      })
    ).rejects.toThrow(/institutionId/);
  });

  // TEST 15 — Malformed timestamps rejection
  it('TEST 15: should reject verification request with malformed timestamps', async () => {
    await expect(
      verificationService.verifyNotice({
        payload: {
          institutionId: sampleInstitution.id,
          title: 'Valid Title',
          content: 'Valid content',
          issuedAt: 'invalid-date-string',
          expiresAt: '2026-12-31T23:59:59.000Z',
        },
        signature: 'dummy_sig',
      })
    ).rejects.toThrow(/Invalid timestamp/);
  });

  // TEST 16 — Missing signature rejection
  it('TEST 16: should reject verification request when signature is omitted or empty', async () => {
    await expect(
      verificationService.verifyNotice({
        payload: {
          institutionId: sampleInstitution.id,
          title: 'Valid Title',
          content: 'Valid content',
          issuedAt: '2026-07-01T00:00:00.000Z',
          expiresAt: '2026-12-31T23:59:59.000Z',
        },
        signature: '',
      })
    ).rejects.toThrow(/signature/);
  });

  // TEST 17 — Content hash mismatch verification
  it('TEST 17: should detect content hash mismatch when expected hash does not match computed hash', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Integrity Check Notice',
      content: 'Original content.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    const forgedContentHash = 'a'.repeat(64); // Invalid expected hash

    const result = await verificationService.verifyNotice({
      payload: {
        noticeId: signedNotice.noticeId,
        institutionId: signedNotice.institutionId,
        title: signedNotice.title,
        content: signedNotice.content,
        issuedAt: signedNotice.issuedAt,
        expiresAt: signedNotice.expiresAt,
      },
      signature: signedNotice.signature,
      contentHash: forgedContentHash,
    });

    expect(result.isAuthentic).toBe(false);
    expect(result.checks.integrityVerified).toBe(false);
  });
});
