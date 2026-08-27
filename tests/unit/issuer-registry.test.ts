import { IssuerRegistryService } from '../../src/services/registry/issuer-registry.service';
import { ed25519Service } from '../../src/services/crypto/ed25519.service';
import { InstitutionRecord, IssuerKeyRecord, KeyStatus } from '../../src/types';
import { PrismaClient } from '@prisma/client';

/**
 * In-memory Mock Prisma Client for hermetic, deterministic unit testing
 * of IssuerRegistryService without requiring external PostgreSQL database.
 */
class InMemoryPrismaMock {
  public institutions: Map<string, InstitutionRecord> = new Map();
  public keys: Map<string, IssuerKeyRecord> = new Map();

  public institution = {
    findUnique: jest.fn(async ({ where }: { where: { id?: string; verifiedDomain?: string } }) => {
      if (where.id) {
        return this.institutions.get(where.id) || null;
      }
      if (where.verifiedDomain) {
        for (const inst of this.institutions.values()) {
          if (inst.verifiedDomain === where.verifiedDomain) {
            return inst;
          }
        }
      }
      return null;
    }),

    create: jest.fn(async ({ data }: { data: any }) => {
      const id = data.id || `inst-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      const record: InstitutionRecord = {
        id,
        name: data.name,
        verifiedDomain: data.verifiedDomain,
        status: data.status || 'PENDING',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      this.institutions.set(id, record);
      return record;
    }),
  };

  public issuerKey = {
    findUnique: jest.fn(async ({ where }: { where: { id?: string; publicKey?: string } }) => {
      if (where.id) {
        return this.keys.get(where.id) || null;
      }
      if (where.publicKey) {
        for (const key of this.keys.values()) {
          if (key.publicKey === where.publicKey) {
            return key;
          }
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

    create: jest.fn(async ({ data }: { data: any }) => {
      const id = data.id || `key-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      const record: IssuerKeyRecord = {
        id,
        institutionId: data.institutionId,
        publicKey: data.publicKey,
        keyStatus: data.keyStatus || 'ACTIVE',
        createdAt: new Date(),
        expiresAt: new Date(data.expiresAt),
        revokedAt: null,
      };
      this.keys.set(id, record);
      return record;
    }),

    update: jest.fn(async ({ where, data }: { where: { id: string }; data: any }) => {
      const existing = this.keys.get(where.id);
      if (!existing) {
        throw new Error(`Record to update not found: ${where.id}`);
      }
      const updated: IssuerKeyRecord = {
        ...existing,
        ...data,
      };
      this.keys.set(where.id, updated);
      return updated;
    }),
  };

  public reset(): void {
    this.institutions.clear();
    this.keys.clear();
    jest.clearAllMocks();
  }
}

describe('Phase 4 — Trusted Issuer Public-Key Registry Tests', () => {
  let mockPrisma: InMemoryPrismaMock;
  let registryService: IssuerRegistryService;
  let sampleInstitution: InstitutionRecord;
  let testKeyPair: { publicKeyBase64: string; privateKeyBase64: string };
  const futureExpiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year in future

  beforeEach(async () => {
    mockPrisma = new InMemoryPrismaMock();
    registryService = new IssuerRegistryService(mockPrisma as unknown as PrismaClient);

    // Setup active registered institution
    sampleInstitution = await mockPrisma.institution.create({
      data: {
        id: 'inst-delhi-university-01',
        name: 'University of Delhi',
        verifiedDomain: 'du.ac.in',
        status: 'ACTIVE',
      },
    });

    testKeyPair = ed25519Service.generateKeyPair();
  });

  // TEST 1 — Register valid Ed25519 public key
  it('TEST 1: should successfully register a valid 32-byte Ed25519 public key for an authorized institution', async () => {
    const keyRecord = await registryService.registerTrustedKey(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64,
      futureExpiry
    );

    expect(keyRecord).toBeDefined();
    expect(keyRecord.id).toBeDefined();
    expect(keyRecord.institutionId).toBe(sampleInstitution.id);
    expect(keyRecord.publicKey).toBe(testKeyPair.publicKeyBase64);
    expect(keyRecord.keyStatus).toBe('ACTIVE');
    expect(keyRecord.revokedAt).toBeNull();
    expect(keyRecord.expiresAt.getTime()).toBe(futureExpiry.getTime());
  });

  // TEST 2 — Retrieve registered active public key
  it('TEST 2: should retrieve the registered active public key for a valid institution', async () => {
    await registryService.registerTrustedKey(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64,
      futureExpiry
    );

    const activeKey = await registryService.getActiveKeyByInstitution(sampleInstitution.id);

    expect(activeKey).not.toBeNull();
    expect(activeKey?.publicKey).toBe(testKeyPair.publicKeyBase64);
    expect(activeKey?.institutionId).toBe(sampleInstitution.id);
    expect(activeKey?.keyStatus).toBe('ACTIVE');

    // Semantic alias test
    const trustedKey = await registryService.getTrustedPublicKey(sampleInstitution.id);
    expect(trustedKey?.publicKey).toBe(testKeyPair.publicKeyBase64);
  });

  // TEST 3 — Malformed Base64 public key
  it('TEST 3: should reject registration and validation of malformed Base64 public keys', async () => {
    const malformedKeys = [
      'not-a-valid-base64!@#$',
      '???invalid???',
      'abc==def',
      '',
      '   ',
    ];

    for (const malformedKey of malformedKeys) {
      await expect(
        registryService.registerTrustedKey(sampleInstitution.id, malformedKey, futureExpiry)
      ).rejects.toThrow();

      const isTrusted = await registryService.isKeyTrusted(sampleInstitution.id, malformedKey);
      expect(isTrusted).toBe(false);
    }
  });

  // TEST 4 — Incorrect decoded public-key length
  it('TEST 4: should reject public keys with incorrect decoded length (not exactly 32 bytes)', async () => {
    const byte16Key = Buffer.alloc(16, 0xaa).toString('base64');
    const byte31Key = Buffer.alloc(31, 0xbb).toString('base64');
    const byte33Key = Buffer.alloc(33, 0xcc).toString('base64');
    const byte64Key = Buffer.alloc(64, 0xdd).toString('base64');

    const invalidLengthKeys = [byte16Key, byte31Key, byte33Key, byte64Key];

    for (const key of invalidLengthKeys) {
      await expect(
        registryService.registerTrustedKey(sampleInstitution.id, key, futureExpiry)
      ).rejects.toThrow(/Invalid Ed25519 public key length/);

      const isTrusted = await registryService.isKeyTrusted(sampleInstitution.id, key);
      expect(isTrusted).toBe(false);
    }
  });

  // TEST 5 — Unknown institution lookup
  it('TEST 5: should return null and false when looking up or validating keys for an unknown institution', async () => {
    const unknownInstId = 'inst-nonexistent-999';

    const activeKey = await registryService.getActiveKeyByInstitution(unknownInstId);
    expect(activeKey).toBeNull();

    const isTrusted = await registryService.isKeyTrusted(unknownInstId, testKeyPair.publicKeyBase64);
    expect(isTrusted).toBe(false);

    // Registration for unknown institution should throw error
    await expect(
      registryService.registerTrustedKey(unknownInstId, testKeyPair.publicKeyBase64, futureExpiry)
    ).rejects.toThrow(/does not exist/);
  });

  // TEST 6 — Duplicate key registration
  it('TEST 6: should safely handle and prevent duplicate active key registration for the same institution', async () => {
    // First registration
    await registryService.registerTrustedKey(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64,
      futureExpiry
    );

    // Second registration of exact same active key
    await expect(
      registryService.registerTrustedKey(
        sampleInstitution.id,
        testKeyPair.publicKeyBase64,
        futureExpiry
      )
    ).rejects.toThrow(/Duplicate registration/);
  });

  // TEST 7 — Conflicting key registration
  it('TEST 7: should prevent conflicting registration where Institution B attempts to claim Institution A’s public key', async () => {
    const instB = await mockPrisma.institution.create({
      data: {
        id: 'inst-iit-bombay-02',
        name: 'IIT Bombay',
        verifiedDomain: 'iitb.ac.in',
        status: 'ACTIVE',
      },
    });

    // Register key for Institution A
    await registryService.registerTrustedKey(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64,
      futureExpiry
    );

    // Institution B attempts to register the same public key
    await expect(
      registryService.registerTrustedKey(instB.id, testKeyPair.publicKeyBase64, futureExpiry)
    ).rejects.toThrow(/Conflicting registration: Public key is already associated with another institution/);
  });

  // TEST 8 — Institution-to-key association
  it('TEST 8: should enforce strict institution-to-key association (Institution A cannot validate Institution B’s key)', async () => {
    const instB = await mockPrisma.institution.create({
      data: {
        id: 'inst-iit-madras-03',
        name: 'IIT Madras',
        verifiedDomain: 'iitm.ac.in',
        status: 'ACTIVE',
      },
    });

    const keyPairB = ed25519Service.generateKeyPair();

    // Register key for Institution B
    await registryService.registerTrustedKey(instB.id, keyPairB.publicKeyBase64, futureExpiry);

    // Verify key B is trusted for Institution B
    const isTrustedForB = await registryService.isKeyTrusted(instB.id, keyPairB.publicKeyBase64);
    expect(isTrustedForB).toBe(true);

    // Cross-check: Key B must NOT be trusted for Institution A (sampleInstitution)
    const isTrustedForA = await registryService.isKeyTrusted(
      sampleInstitution.id,
      keyPairB.publicKeyBase64
    );
    expect(isTrustedForA).toBe(false);

    // Active key for Institution A must remain null
    const activeKeyA = await registryService.getActiveKeyByInstitution(sampleInstitution.id);
    expect(activeKeyA).toBeNull();
  });

  // TEST 9 — Revoked key
  it('TEST 9: should ensure a revoked key is never returned as an active trusted verification key', async () => {
    const keyRecord = await registryService.registerTrustedKey(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64,
      futureExpiry
    );

    // Key is initially active and trusted
    expect(await registryService.isKeyTrusted(sampleInstitution.id, testKeyPair.publicKeyBase64)).toBe(true);

    // Revoke the key
    const revoked = await registryService.revokeKey(keyRecord.id, 'Key compromised in security audit');
    expect(revoked.keyStatus).toBe('REVOKED');
    expect(revoked.revokedAt).not.toBeNull();

    // Key must no longer be returned as active
    const activeKey = await registryService.getActiveKeyByInstitution(sampleInstitution.id);
    expect(activeKey).toBeNull();

    // isKeyTrusted must return false
    const isTrusted = await registryService.isKeyTrusted(sampleInstitution.id, testKeyPair.publicKeyBase64);
    expect(isTrusted).toBe(false);

    // Re-registration of a revoked key must be rejected
    await expect(
      registryService.registerTrustedKey(sampleInstitution.id, testKeyPair.publicKeyBase64, futureExpiry)
    ).rejects.toThrow(/revoked public key cannot be re-registered/);
  });

  // TEST 10 — Expired key
  it('TEST 10: should ensure an expired key is never returned as an active trusted verification key', async () => {
    // Direct registration with past expiry date must be rejected
    const pastExpiry = new Date(Date.now() - 24 * 60 * 60 * 1000); // 1 day in the past

    await expect(
      registryService.registerTrustedKey(sampleInstitution.id, testKeyPair.publicKeyBase64, pastExpiry)
    ).rejects.toThrow(/expiration date must be in the future/);

    // Register with short lifetime, then simulate time passing
    const shortExpiry = new Date(Date.now() + 50); // 50ms in future
    await registryService.registerTrustedKey(sampleInstitution.id, testKeyPair.publicKeyBase64, shortExpiry);

    // Wait for key to expire
    await new Promise((resolve) => setTimeout(resolve, 80));

    const activeKey = await registryService.getActiveKeyByInstitution(sampleInstitution.id);
    expect(activeKey).toBeNull();

    const isTrusted = await registryService.isKeyTrusted(sampleInstitution.id, testKeyPair.publicKeyBase64);
    expect(isTrusted).toBe(false);
  });

  // TEST 11 — Private-key protection
  it('TEST 11: should strictly reject private key material and never store or expose private keys in the registry', async () => {
    // Attempting to register private key in PEM format
    const dummyPemPrivateKey = `-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIK7gNu3s9yqXvR5a6789012345678901234567890123\n-----END PRIVATE KEY-----`;

    await expect(
      registryService.registerTrustedKey(sampleInstitution.id, dummyPemPrivateKey, futureExpiry)
    ).rejects.toThrow(/private key material must never be submitted/);

    // Attempting to register raw 64-byte private seed/expanded key
    const raw64ByteSecret = Buffer.alloc(64, 0xee).toString('base64');
    await expect(
      registryService.registerTrustedKey(sampleInstitution.id, raw64ByteSecret, futureExpiry)
    ).rejects.toThrow(/Invalid Ed25519 public key length/);

    // Verify registered record does not contain any private key fields
    const validKeyRecord = await registryService.registerTrustedKey(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64,
      futureExpiry
    );

    expect((validKeyRecord as any).privateKey).toBeUndefined();
    expect((validKeyRecord as any).privateKeyBase64).toBeUndefined();
    expect((validKeyRecord as any).secret).toBeUndefined();
  });

  // TEST 12 — Arbitrary client public-key protection
  it('TEST 12: should not trust an arbitrary valid Ed25519 public key supplied out-of-band by a client', async () => {
    // Register Institution A with Key A
    await registryService.registerTrustedKey(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64,
      futureExpiry
    );

    // Client generates an arbitrary valid Ed25519 keypair
    const arbitraryClientKeyPair = ed25519Service.generateKeyPair();
    expect(ed25519Service.validatePublicKey(arbitraryClientKeyPair.publicKeyBase64)).toBe(true);

    // Client provides arbitrary key claiming it belongs to Institution A
    const isArbitraryKeyTrusted = await registryService.isKeyTrusted(
      sampleInstitution.id,
      arbitraryClientKeyPair.publicKeyBase64
    );

    expect(isArbitraryKeyTrusted).toBe(false);

    // Only the official registered key from the registry is trusted
    const isRegistryKeyTrusted = await registryService.isKeyTrusted(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64
    );
    expect(isRegistryKeyTrusted).toBe(true);
  });

  // Additional Test — Suspended institution handling
  it('should reject key registration and lookup for suspended institutions', async () => {
    const suspendedInst = await mockPrisma.institution.create({
      data: {
        id: 'inst-suspended-college-04',
        name: 'Suspended College',
        verifiedDomain: 'suspended.edu',
        status: 'SUSPENDED',
      },
    });

    await expect(
      registryService.registerTrustedKey(suspendedInst.id, testKeyPair.publicKeyBase64, futureExpiry)
    ).rejects.toThrow(/is currently suspended/);

    const activeKey = await registryService.getActiveKeyByInstitution(suspendedInst.id);
    expect(activeKey).toBeNull();
  });

  // Additional Test — Revoke key by public key string and institution ID
  it('should successfully revoke key by public key string and institution association', async () => {
    await registryService.registerTrustedKey(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64,
      futureExpiry
    );

    const revoked = await registryService.revokeKeyByPublicKey(
      sampleInstitution.id,
      testKeyPair.publicKeyBase64,
      'Scheduled key rotation'
    );

    expect(revoked.keyStatus).toBe('REVOKED');
    expect(await registryService.isKeyTrusted(sampleInstitution.id, testKeyPair.publicKeyBase64)).toBe(false);
  });
});
