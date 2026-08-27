import { NoticeService, NoticeRecord } from '../../src/services/notice/notice.service';
import { IssuerRegistryService } from '../../src/services/registry/issuer-registry.service';
import { ed25519Service } from '../../src/services/crypto/ed25519.service';
import { hashingService } from '../../src/services/crypto/hashing.service';
import { canonicalizationService } from '../../src/services/crypto/canonicalization.service';
import {
  InstitutionRecord,
  IssuerKeyRecord,
  NoticeCreateDto,
  NoticeCanonicalPayload,
  KeyStatus,
} from '../../src/types';
import { PrismaClient } from '@prisma/client';

/**
 * In-memory Mock Prisma Client for hermetic testing of NoticeService.
 */
class InMemoryNoticePrismaMock {
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

    update: jest.fn(async ({ where, data }: { where: { id: string }; data: any }) => {
      const existing = this.notices.get(where.id);
      if (!existing) throw new Error(`Notice not found: ${where.id}`);
      const updated = { ...existing, ...data, updatedAt: new Date() };
      this.notices.set(where.id, updated);
      return updated;
    }),
  };

  public reset(): void {
    this.institutions.clear();
    this.keys.clear();
    this.notices.clear();
    jest.clearAllMocks();
  }
}

describe('Phase 5 — Notice Creation & Cryptographic Signing Workflow Tests', () => {
  let mockPrisma: InMemoryNoticePrismaMock;
  let registryService: IssuerRegistryService;
  let noticeService: NoticeService;
  let sampleInstitution: InstitutionRecord;
  let institutionKeyPair: { publicKeyBase64: string; privateKeyBase64: string };
  const futureExpiry = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000); // 180 days in future

  beforeEach(() => {
    mockPrisma = new InMemoryNoticePrismaMock();
    registryService = new IssuerRegistryService(mockPrisma as unknown as PrismaClient);
    noticeService = new NoticeService(mockPrisma as unknown as PrismaClient, registryService);

    // Create an active institution in mock database
    sampleInstitution = {
      id: 'inst-delhi-university-01',
      name: 'University of Delhi',
      verifiedDomain: 'du.ac.in',
      status: 'ACTIVE',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    mockPrisma.institutions.set(sampleInstitution.id, sampleInstitution);

    // Generate fresh Ed25519 keypair for institution
    institutionKeyPair = ed25519Service.generateKeyPair();

    // Register active public key in registry
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

    // Configure server-side secure signing key for the institution
    noticeService.setInstitutionSigningKey(sampleInstitution.id, institutionKeyPair.privateKeyBase64);
  });

  // TEST 1 — Valid notice creation and signing
  it('TEST 1: should allow a valid institution to create and sign an authentic notice', async () => {
    const noticeDto: NoticeCreateDto = {
      institutionId: sampleInstitution.id,
      title: 'End Semester Examination Schedule 2026',
      content: 'The end-semester examinations will commence on May 10, 2026.',
      issuedAt: '2026-04-01T10:00:00.000Z',
      expiresAt: '2026-06-30T23:59:59.000Z',
      metadata: { department: 'Examination Branch', semester: 6 },
    };

    const signedNotice = await noticeService.createAndSignNotice(noticeDto);

    expect(signedNotice).toBeDefined();
    expect(signedNotice.id).toBeDefined();
    expect(signedNotice.institutionId).toBe(sampleInstitution.id);
    expect(signedNotice.title).toBe(noticeDto.title);
    expect(signedNotice.content).toBe(noticeDto.content);
    expect(signedNotice.contentHash).toBeDefined();
    expect(signedNotice.signature).toBeDefined();
    expect(signedNotice.signatureAlgorithm).toBe('Ed25519');
    expect(signedNotice.status).toBe('ACTIVE');
  });

  // TEST 2 — Signed notice contains a valid SHA-256 hash
  it('TEST 2: should generate a deterministic 64-character lowercase SHA-256 content hash', async () => {
    const noticeDto: NoticeCreateDto = {
      institutionId: sampleInstitution.id,
      title: 'Annual Convocation Ceremony 2026',
      content: 'Official convocation ceremony will take place at the main sports complex.',
      expiresAt: '2026-12-31T23:59:59.000Z',
    };

    const signedNotice = await noticeService.createAndSignNotice(noticeDto);

    expect(signedNotice.contentHash).toHaveLength(64);
    expect(signedNotice.contentHash).toMatch(/^[a-f0-9]{64}$/);

    // Compute expected hash independently using Phase 2 canonicalization
    const canonicalPayload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: sampleInstitution.id,
      title: noticeDto.title,
      content: noticeDto.content,
      issuedAt: signedNotice.issuedAt,
      expiresAt: signedNotice.expiresAt,
    };
    const expectedHash = hashingService.hashCanonicalPayload(canonicalPayload);

    expect(signedNotice.contentHash).toBe(expectedHash);
  });

  // TEST 3 — Signature can be verified using Phase 3 verification
  it('TEST 3: should produce an Ed25519 signature verifiable with the institution public key', async () => {
    const noticeDto: NoticeCreateDto = {
      institutionId: sampleInstitution.id,
      title: 'Faculty Recruitment Notification 2026',
      content: 'Applications are invited for Assistant Professor positions across departments.',
      expiresAt: '2026-08-31T23:59:59.000Z',
      metadata: { advertisementNumber: 'DU/REC/2026/01' },
    };

    const signedNotice = await noticeService.createAndSignNotice(noticeDto);

    const canonicalPayload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: signedNotice.institutionId,
      title: signedNotice.title,
      content: signedNotice.content,
      issuedAt: signedNotice.issuedAt,
      expiresAt: signedNotice.expiresAt,
      metadata: signedNotice.metadata,
    };

    const isValid = ed25519Service.verifyNoticePayload(
      canonicalPayload,
      signedNotice.signature,
      institutionKeyPair.publicKeyBase64
    );

    expect(isValid).toBe(true);
  });

  // TEST 4 — Changing the title after signing causes verification failure
  it('TEST 4: should fail verification if notice title is modified after signing', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Original Notice Title',
      content: 'Official circular text.',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    const tamperedPayload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: signedNotice.institutionId,
      title: 'Forged / Altered Title',
      content: signedNotice.content,
      issuedAt: signedNotice.issuedAt,
      expiresAt: signedNotice.expiresAt,
    };

    const isValid = ed25519Service.verifyNoticePayload(
      tamperedPayload,
      signedNotice.signature,
      institutionKeyPair.publicKeyBase64
    );

    expect(isValid).toBe(false);
  });

  // TEST 5 — Changing content after signing causes verification failure
  it('TEST 5: should fail verification if notice content is modified after signing', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Holiday Notification',
      content: 'Campus will remain closed on Friday.',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    const tamperedPayload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: signedNotice.institutionId,
      title: signedNotice.title,
      content: 'Tampered: Campus will remain OPEN with mandatory attendance.',
      issuedAt: signedNotice.issuedAt,
      expiresAt: signedNotice.expiresAt,
    };

    const isValid = ed25519Service.verifyNoticePayload(
      tamperedPayload,
      signedNotice.signature,
      institutionKeyPair.publicKeyBase64
    );

    expect(isValid).toBe(false);
  });

  // TEST 6 — Changing issuedAt after signing invalidates verification
  it('TEST 6: should fail verification if issuedAt timestamp is altered after signing', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Fee Payment Deadline',
      content: 'Pay by April 30.',
      issuedAt: '2026-04-01T00:00:00.000Z',
      expiresAt: '2026-04-30T23:59:59.000Z',
    });

    const tamperedPayload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: signedNotice.institutionId,
      title: signedNotice.title,
      content: signedNotice.content,
      issuedAt: '2026-04-05T00:00:00.000Z', // Tampered date
      expiresAt: signedNotice.expiresAt,
    };

    const isValid = ed25519Service.verifyNoticePayload(
      tamperedPayload,
      signedNotice.signature,
      institutionKeyPair.publicKeyBase64
    );

    expect(isValid).toBe(false);
  });

  // TEST 7 — Changing expiresAt after signing invalidates verification
  it('TEST 7: should fail verification if expiresAt timestamp is altered after signing', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Scholarship Applications Open',
      content: 'Submit application before deadline.',
      issuedAt: '2026-05-01T00:00:00.000Z',
      expiresAt: '2026-05-31T23:59:59.000Z',
    });

    const tamperedPayload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: signedNotice.institutionId,
      title: signedNotice.title,
      content: signedNotice.content,
      issuedAt: signedNotice.issuedAt,
      expiresAt: '2026-12-31T23:59:59.000Z', // Forged extended deadline
    };

    const isValid = ed25519Service.verifyNoticePayload(
      tamperedPayload,
      signedNotice.signature,
      institutionKeyPair.publicKeyBase64
    );

    expect(isValid).toBe(false);
  });

  // TEST 8 — Changing metadata invalidates verification
  it('TEST 8: should fail verification if signed metadata object is modified after signing', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Hostel Allotment List 2026',
      content: 'List of allotted students published on bulletin board.',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-07-31T23:59:59.000Z',
      metadata: { quota: 'Merit', feeRefundable: false },
    });

    const tamperedPayload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: signedNotice.institutionId,
      title: signedNotice.title,
      content: signedNotice.content,
      issuedAt: signedNotice.issuedAt,
      expiresAt: signedNotice.expiresAt,
      metadata: { quota: 'Management', feeRefundable: true }, // Altered metadata
    };

    const isValid = ed25519Service.verifyNoticePayload(
      tamperedPayload,
      signedNotice.signature,
      institutionKeyPair.publicKeyBase64
    );

    expect(isValid).toBe(false);
  });

  // TEST 9 — Empty title is rejected
  it('TEST 9: should reject notice creation when title is empty or whitespace only', async () => {
    await expect(
      noticeService.createAndSignNotice({
        institutionId: sampleInstitution.id,
        title: '',
        content: 'Valid content',
        expiresAt: '2026-12-31T23:59:59.000Z',
      })
    ).rejects.toThrow(/title.*required/i);

    await expect(
      noticeService.createAndSignNotice({
        institutionId: sampleInstitution.id,
        title: '   ',
        content: 'Valid content',
        expiresAt: '2026-12-31T23:59:59.000Z',
      })
    ).rejects.toThrow(/title.*required/i);
  });

  // TEST 10 — Empty content is rejected
  it('TEST 10: should reject notice creation when content is empty or whitespace only', async () => {
    await expect(
      noticeService.createAndSignNotice({
        institutionId: sampleInstitution.id,
        title: 'Valid Title',
        content: '',
        expiresAt: '2026-12-31T23:59:59.000Z',
      })
    ).rejects.toThrow(/content.*required/i);
  });

  // TEST 11 — Invalid issuedAt is rejected
  it('TEST 11: should reject notice creation with malformed issuedAt timestamp', async () => {
    await expect(
      noticeService.createAndSignNotice({
        institutionId: sampleInstitution.id,
        title: 'Valid Title',
        content: 'Valid content',
        issuedAt: 'not-a-date',
        expiresAt: '2026-12-31T23:59:59.000Z',
      })
    ).rejects.toThrow(/Invalid "issuedAt" timestamp/);
  });

  // TEST 12 — Invalid expiresAt is rejected
  it('TEST 12: should reject notice creation with malformed expiresAt timestamp', async () => {
    await expect(
      noticeService.createAndSignNotice({
        institutionId: sampleInstitution.id,
        title: 'Valid Title',
        content: 'Valid content',
        expiresAt: 'invalid-expiry-format',
      })
    ).rejects.toThrow(/Invalid "expiresAt" timestamp/);
  });

  // TEST 13 — expiresAt <= issuedAt is rejected
  it('TEST 13: should reject notice creation when expiresAt is equal to or earlier than issuedAt', async () => {
    // Expiry earlier than issuedAt
    await expect(
      noticeService.createAndSignNotice({
        institutionId: sampleInstitution.id,
        title: 'Valid Title',
        content: 'Valid content',
        issuedAt: '2026-05-01T10:00:00.000Z',
        expiresAt: '2026-04-01T10:00:00.000Z',
      })
    ).rejects.toThrow(/expiresAt.*strictly later than.*issuedAt/);

    // Expiry exactly equal to issuedAt
    await expect(
      noticeService.createAndSignNotice({
        institutionId: sampleInstitution.id,
        title: 'Valid Title',
        content: 'Valid content',
        issuedAt: '2026-05-01T10:00:00.000Z',
        expiresAt: '2026-05-01T10:00:00.000Z',
      })
    ).rejects.toThrow(/expiresAt.*strictly later than.*issuedAt/);
  });

  // TEST 14 — Unknown institution cannot create a signed notice
  it('TEST 14: should reject notice creation for non-existent institution ID', async () => {
    await expect(
      noticeService.createAndSignNotice({
        institutionId: 'inst-unknown-999',
        title: 'Unauthorized Notice',
        content: 'Attempted forged notice',
        expiresAt: '2026-12-31T23:59:59.000Z',
      })
    ).rejects.toThrow(/does not exist/);
  });

  // TEST 15 — Institution without trusted key cannot create notice
  it('TEST 15: should reject notice creation for institution without registered active public key', async () => {
    const instNoKey: InstitutionRecord = {
      id: 'inst-iit-roorkee-02',
      name: 'IIT Roorkee',
      verifiedDomain: 'iitr.ac.in',
      status: 'ACTIVE',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    mockPrisma.institutions.set(instNoKey.id, instNoKey);

    await expect(
      noticeService.createAndSignNotice({
        institutionId: instNoKey.id,
        title: 'Notice Without Key',
        content: 'Should fail because no key is registered.',
        expiresAt: '2026-12-31T23:59:59.000Z',
      })
    ).rejects.toThrow(/No active trusted Ed25519 public key found/);
  });

  // TEST 16 — Revoked issuer key cannot be used
  it('TEST 16: should reject notice creation when institution public key has been revoked', async () => {
    const key = mockPrisma.keys.get('key-du-active-01')!;
    key.keyStatus = 'REVOKED';
    key.revokedAt = new Date();

    await expect(
      noticeService.createAndSignNotice({
        institutionId: sampleInstitution.id,
        title: 'Notice With Revoked Key',
        content: 'Cannot sign with revoked key.',
        expiresAt: '2026-12-31T23:59:59.000Z',
      })
    ).rejects.toThrow(/No active trusted Ed25519 public key found/);
  });

  // TEST 17 — Expired issuer key cannot be used
  it('TEST 17: should reject notice creation when institution public key has expired', async () => {
    const key = mockPrisma.keys.get('key-du-active-01')!;
    key.expiresAt = new Date(Date.now() - 1000); // 1 second ago

    await expect(
      noticeService.createAndSignNotice({
        institutionId: sampleInstitution.id,
        title: 'Notice With Expired Key',
        content: 'Cannot sign with expired key.',
        expiresAt: '2026-12-31T23:59:59.000Z',
      })
    ).rejects.toThrow(/No active trusted Ed25519 public key found/);
  });

  // TEST 18 — Client cannot supply arbitrary public key
  it('TEST 18: should ignore or reject client-supplied arbitrary public key and use registry key only', async () => {
    const arbitraryKeyPair = ed25519Service.generateKeyPair();

    const noticeWithArbitraryKey: any = {
      institutionId: sampleInstitution.id,
      title: 'Attempted Arbitrary Public Key Override',
      content: 'Notice content.',
      expiresAt: '2026-12-31T23:59:59.000Z',
      publicKey: arbitraryKeyPair.publicKeyBase64, // Client attempts to override
    };

    const signedNotice = await noticeService.createAndSignNotice(noticeWithArbitraryKey);

    // The signature must verify against the REGISTRY key, NOT the client's arbitrary key
    const canonicalPayload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: signedNotice.institutionId,
      title: signedNotice.title,
      content: signedNotice.content,
      issuedAt: signedNotice.issuedAt,
      expiresAt: signedNotice.expiresAt,
    };

    expect(
      ed25519Service.verifyNoticePayload(
        canonicalPayload,
        signedNotice.signature,
        institutionKeyPair.publicKeyBase64
      )
    ).toBe(true);

    expect(
      ed25519Service.verifyNoticePayload(
        canonicalPayload,
        signedNotice.signature,
        arbitraryKeyPair.publicKeyBase64
      )
    ).toBe(false);
  });

  // TEST 19 — Client cannot provide private key in request
  it('TEST 19: should ignore client-supplied private key in payload and use secure server context', async () => {
    const forgedPrivateKey = ed25519Service.generateKeyPair().privateKeyBase64;

    const noticeWithClientSecret: any = {
      institutionId: sampleInstitution.id,
      title: 'Official Circular',
      content: 'Standard content.',
      expiresAt: '2026-12-31T23:59:59.000Z',
      privateKey: forgedPrivateKey, // Client attempts to inject private key
      privateKeyBase64: forgedPrivateKey,
    };

    const signedNotice = await noticeService.createAndSignNotice(noticeWithClientSecret);

    // Output must not include the client's private key
    expect((signedNotice as any).privateKey).toBeUndefined();
    expect((signedNotice as any).privateKeyBase64).toBeUndefined();

    // Verify against legitimate registry key
    const canonicalPayload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: signedNotice.institutionId,
      title: signedNotice.title,
      content: signedNotice.content,
      issuedAt: signedNotice.issuedAt,
      expiresAt: signedNotice.expiresAt,
    };

    expect(
      ed25519Service.verifyNoticePayload(
        canonicalPayload,
        signedNotice.signature,
        institutionKeyPair.publicKeyBase64
      )
    ).toBe(true);
  });

  // TEST 20 — Private key never appears in API response
  it('TEST 20: should never include private key material in signed notice response object', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Clean Response Verification',
      content: 'Verification that no secrets leak.',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    const responseKeys = Object.keys(signedNotice);
    expect(responseKeys).not.toContain('privateKey');
    expect(responseKeys).not.toContain('privateKeyBase64');
    expect(responseKeys).not.toContain('secret');
    expect(responseKeys).not.toContain('keySeed');
    expect(JSON.stringify(signedNotice)).not.toContain(institutionKeyPair.privateKeyBase64);
  });

  // TEST 21 — Private key is not persisted in database
  it('TEST 21: should never store private keys in the notice database record', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Database Record Audit',
      content: 'Checking database persistence integrity.',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    const dbRecord = mockPrisma.notices.get(signedNotice.id);
    expect(dbRecord).toBeDefined();
    expect((dbRecord as any).privateKey).toBeUndefined();
    expect((dbRecord as any).privateKeyBase64).toBeUndefined();
  });

  // TEST 22 — Repeated deterministic processing produces consistent results
  it('TEST 22: should produce identical canonical string, content hash, and Ed25519 signature for identical inputs', async () => {
    const fixedIssuedAt = '2026-04-01T00:00:00.000Z';
    const fixedExpiresAt = '2026-06-30T23:59:59.000Z';

    const payload1: NoticeCreateDto = {
      noticeId: 'fixed-notice-uuid-01',
      institutionId: sampleInstitution.id,
      title: 'Deterministic Notice Test',
      content: 'Exact same deterministic content string.',
      issuedAt: fixedIssuedAt,
      expiresAt: fixedExpiresAt,
      metadata: { bKey: 2, aKey: 1 },
    };

    const payload2: NoticeCreateDto = {
      noticeId: 'fixed-notice-uuid-01',
      institutionId: sampleInstitution.id,
      title: 'Deterministic Notice Test',
      content: 'Exact same deterministic content string.',
      issuedAt: fixedIssuedAt,
      expiresAt: fixedExpiresAt,
      metadata: { aKey: 1, bKey: 2 }, // Different key order in input object
    };

    const res1 = await noticeService.createAndSignNotice(payload1);
    const res2 = await noticeService.createAndSignNotice(payload2);

    expect(res1.contentHash).toBe(res2.contentHash);
    expect(res1.signature).toBe(res2.signature);
  });

  // TEST 23 — Phase 3 signature verification compatibility
  it('TEST 23: should remain 100% compatible with Phase 3 verifyNoticePayload verification', async () => {
    const signedNotice = await noticeService.createAndSignNotice({
      institutionId: sampleInstitution.id,
      title: 'Phase 3 Verification Interoperability',
      content: 'Testing verification compatibility across modules.',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    const payload: NoticeCanonicalPayload = {
      noticeId: signedNotice.noticeId,
      institutionId: signedNotice.institutionId,
      title: signedNotice.title,
      content: signedNotice.content,
      issuedAt: signedNotice.issuedAt,
      expiresAt: signedNotice.expiresAt,
    };

    const isVerified = ed25519Service.verifyNoticePayload(
      payload,
      signedNotice.signature,
      institutionKeyPair.publicKeyBase64
    );

    expect(isVerified).toBe(true);
  });
});
