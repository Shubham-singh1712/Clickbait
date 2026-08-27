import { ed25519Service } from '../../src/services/crypto/ed25519.service';
import { NoticeCanonicalPayload } from '../../src/types';

describe('Phase 3 — Ed25519 Signing & Verification Engine Tests', () => {
  let testKeyPair: { publicKeyBase64: string; privateKeyBase64: string };
  let validNotice: NoticeCanonicalPayload;

  beforeEach(() => {
    testKeyPair = ed25519Service.generateKeyPair();
    validNotice = {
      institutionId: 'inst-univ-delhi-01',
      title: 'End Semester Examination Notice 2026',
      content: 'Official exam schedule for all undergraduate programs.',
      issuedAt: '2026-04-01T10:00:00.000Z',
      expiresAt: '2026-06-30T23:59:59.000Z',
      metadata: {
        department: 'Examination Branch',
        academicYear: '2025-2026',
      },
    };
  });

  // TEST 1 — Key generation and valid signing
  it('TEST 1: should generate an Ed25519 keypair and sign a valid canonical notice payload', () => {
    expect(testKeyPair.publicKeyBase64).toBeDefined();
    expect(testKeyPair.privateKeyBase64).toBeDefined();

    // Base64 decoded lengths
    const pubBytes = Buffer.from(testKeyPair.publicKeyBase64, 'base64');
    const privBytes = Buffer.from(testKeyPair.privateKeyBase64, 'base64');
    expect(pubBytes.length).toBe(32);
    expect(privBytes.length).toBe(32);

    const signature = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);
    expect(signature).toBeDefined();
    expect(typeof signature).toBe('string');

    const sigBytes = Buffer.from(signature, 'base64');
    expect(sigBytes.length).toBe(64);
  });

  // TEST 2 — Valid signature verification
  it('TEST 2: should verify a valid Ed25519 signature successfully', () => {
    const signature = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);
    const isValid = ed25519Service.verifyNoticePayload(validNotice, signature, testKeyPair.publicKeyBase64);
    expect(isValid).toBe(true);
  });

  // TEST 3 — Tampered notice content
  it('TEST 3: should fail verification when notice content is altered after signing', () => {
    const signature = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);

    const tamperedNotice: NoticeCanonicalPayload = {
      ...validNotice,
      content: 'Tampered exam schedule with forged dates.',
    };

    const isValid = ed25519Service.verifyNoticePayload(tamperedNotice, signature, testKeyPair.publicKeyBase64);
    expect(isValid).toBe(false);
  });

  // TEST 4 — Tampered institution ID
  it('TEST 4: should fail verification when institution ID is altered after signing', () => {
    const signature = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);

    const tamperedNotice: NoticeCanonicalPayload = {
      ...validNotice,
      institutionId: 'inst-forged-college-99',
    };

    const isValid = ed25519Service.verifyNoticePayload(tamperedNotice, signature, testKeyPair.publicKeyBase64);
    expect(isValid).toBe(false);
  });

  // TEST 5 — Tampered expiry timestamp
  it('TEST 5: should fail verification when expiresAt timestamp is altered after signing', () => {
    const signature = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);

    const tamperedNotice: NoticeCanonicalPayload = {
      ...validNotice,
      expiresAt: '2026-12-31T23:59:59.000Z',
    };

    const isValid = ed25519Service.verifyNoticePayload(tamperedNotice, signature, testKeyPair.publicKeyBase64);
    expect(isValid).toBe(false);
  });

  // TEST 6 — Wrong public key
  it('TEST 6: should fail verification when verifying against a different public key', () => {
    const signature = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);
    const anotherKeyPair = ed25519Service.generateKeyPair();

    const isValid = ed25519Service.verifyNoticePayload(validNotice, signature, anotherKeyPair.publicKeyBase64);
    expect(isValid).toBe(false);
  });

  // TEST 7 — Tampered signature byte
  it('TEST 7: should fail verification when a single byte of the signature is modified', () => {
    const signature = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);
    const sigBuffer = Buffer.from(signature, 'base64');

    // Flip the first byte
    sigBuffer[0] = sigBuffer[0] ^ 0xff;
    const corruptedSignature = sigBuffer.toString('base64');

    const isValid = ed25519Service.verifyNoticePayload(validNotice, corruptedSignature, testKeyPair.publicKeyBase64);
    expect(isValid).toBe(false);
  });

  // TEST 8 — Malformed Base64 public key
  it('TEST 8: should safely reject a malformed Base64 public key without crashing', () => {
    const signature = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);
    const malformedKeys = [
      'not-a-valid-base64-string!@#$%',
      '???invalid???',
      '',
      '   ',
    ];

    for (const malformedKey of malformedKeys) {
      expect(ed25519Service.validatePublicKey(malformedKey)).toBe(false);
      expect(ed25519Service.verifyNoticePayload(validNotice, signature, malformedKey)).toBe(false);
    }
  });

  // TEST 9 — Wrong-length public key
  it('TEST 9: should safely reject public keys with incorrect decoded byte length (not 32 bytes)', () => {
    const signature = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);

    // 16 bytes, 31 bytes, 33 bytes, 64 bytes
    const shortKey = Buffer.alloc(16, 0x01).toString('base64');
    const byte31Key = Buffer.alloc(31, 0x01).toString('base64');
    const byte33Key = Buffer.alloc(33, 0x01).toString('base64');
    const longKey = Buffer.alloc(64, 0x01).toString('base64');

    expect(ed25519Service.validatePublicKey(shortKey)).toBe(false);
    expect(ed25519Service.validatePublicKey(byte31Key)).toBe(false);
    expect(ed25519Service.validatePublicKey(byte33Key)).toBe(false);
    expect(ed25519Service.validatePublicKey(longKey)).toBe(false);

    expect(ed25519Service.verifyNoticePayload(validNotice, signature, shortKey)).toBe(false);
    expect(ed25519Service.verifyNoticePayload(validNotice, signature, byte33Key)).toBe(false);
  });

  // TEST 10 — Malformed Base64 signature
  it('TEST 10: should safely reject a malformed Base64 signature without crashing', () => {
    const malformedSignatures = [
      'not-a-valid-signature!@#$%',
      '???invalid???',
      '',
    ];

    for (const malformedSig of malformedSignatures) {
      expect(ed25519Service.validateSignature(malformedSig)).toBe(false);
      expect(ed25519Service.verifyNoticePayload(validNotice, malformedSig, testKeyPair.publicKeyBase64)).toBe(false);
    }
  });

  // TEST 11 — Wrong-length signature
  it('TEST 11: should safely reject signatures with incorrect decoded byte length (not 64 bytes)', () => {
    const byte32Sig = Buffer.alloc(32, 0x01).toString('base64');
    const byte63Sig = Buffer.alloc(63, 0x01).toString('base64');
    const byte65Sig = Buffer.alloc(65, 0x01).toString('base64');

    expect(ed25519Service.validateSignature(byte32Sig)).toBe(false);
    expect(ed25519Service.validateSignature(byte63Sig)).toBe(false);
    expect(ed25519Service.validateSignature(byte65Sig)).toBe(false);

    expect(ed25519Service.verifyNoticePayload(validNotice, byte32Sig, testKeyPair.publicKeyBase64)).toBe(false);
    expect(ed25519Service.verifyNoticePayload(validNotice, byte65Sig, testKeyPair.publicKeyBase64)).toBe(false);
  });

  // TEST 12 — Unicode / multilingual notice content
  it('TEST 12: should accurately sign and verify notice payloads with multilingual Unicode characters', () => {
    const unicodeNotice: NoticeCanonicalPayload = {
      institutionId: 'inst-iit-delhi-01',
      title: 'अधिसूचना: दीक्षांत समारोह २०२६ (Convocation Ceremony)',
      content: 'विश्वविद्यालय का ५०वां दीक्षांत समारोह १५ मई २०२६ को आयोजित होगा। शुल्क: ₹५००।',
      issuedAt: '2026-04-01T00:00:00.000Z',
      expiresAt: '2026-05-20T23:59:59.000Z',
      metadata: {
        venue: 'मुख्य सभागार (Main Auditorium) 🏛️',
        contact: 'परीक्षा विभाग ✉️',
      },
    };

    const signature = ed25519Service.signNoticePayload(unicodeNotice, testKeyPair.privateKeyBase64);
    const isValid = ed25519Service.verifyNoticePayload(unicodeNotice, signature, testKeyPair.publicKeyBase64);

    expect(isValid).toBe(true);
  });

  // TEST 13 — Deterministic signing
  it('TEST 13: should produce identical Ed25519 signatures for identical canonical payloads and private keys', () => {
    const sig1 = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);
    const sig2 = ed25519Service.signNoticePayload({ ...validNotice }, testKeyPair.privateKeyBase64);
    const sig3 = ed25519Service.signNoticePayload(validNotice, testKeyPair.privateKeyBase64);

    expect(sig1).toBe(sig2);
    expect(sig2).toBe(sig3);
  });

  // TEST 14 — Private key leakage protection in errors & outputs
  it('TEST 14: should never include private key material in error messages when invalid signing inputs occur', () => {
    const dummyPrivateSecret = 'SECRET_PRIVATE_SEED_MATERIAL_ABC123';

    try {
      ed25519Service.sign('Some notice content', dummyPrivateSecret);
      // If sign didn't throw, fail
      expect(true).toBe(false);
    } catch (error) {
      const errorMessage = (error as Error).message;
      expect(errorMessage).not.toContain(dummyPrivateSecret);
      expect(errorMessage).toContain('Invalid Ed25519 private key');
    }
  });
});
