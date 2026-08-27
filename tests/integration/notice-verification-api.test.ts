import request from 'supertest';
import { app } from '../../src/app';
import { ed25519Service } from '../../src/services/crypto/ed25519.service';
import { canonicalizationService } from '../../src/services/crypto/canonicalization.service';

describe('Notice Verification API Integration Tests (Phase 6)', () => {
  jest.setTimeout(15000);
  let keyPair: { publicKeyBase64: string; privateKeyBase64: string };
  const samplePayload = {
    institutionId: 'inst-delhi-university-01',
    title: 'Autumn 2026 Semester Guidelines',
    content: 'All departments will follow standard schedule.',
    issuedAt: '2026-07-01T00:00:00.000Z',
    expiresAt: '2026-12-31T23:59:59.000Z',
  };

  beforeEach(() => {
    keyPair = ed25519Service.generateKeyPair();
  });

  describe('POST /api/verify', () => {
    it('should process verification request and return standardized verification result', async () => {
      const canonicalStr = canonicalizationService.canonicalizeNoticePayload(samplePayload);
      const signature = ed25519Service.sign(canonicalStr, keyPair.privateKeyBase64);

      const response = await request(app)
        .post('/api/verify')
        .send({
          payload: samplePayload,
          signature,
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('isAuthentic');
      expect(response.body.data).toHaveProperty('resultStatus');
      expect(response.body.data).toHaveProperty('checks');
      expect(response.body.data.checks).toHaveProperty('signatureValid');
      expect(response.body.data.checks).toHaveProperty('integrityVerified');
      expect(response.body.data.checks).toHaveProperty('notExpired');
      expect(response.body.data.checks).toHaveProperty('notRevoked');
      expect(response.body.data.checks).toHaveProperty('trustedIssuerKey');

      // Security check: Never expose secrets or private keys
      expect(response.body.data.privateKey).toBeUndefined();
      expect(response.body.data.secret).toBeUndefined();
      expect(response.body.data.privateKeyBase64).toBeUndefined();
    });

    it('should return 400 when request body is empty', async () => {
      const response = await request(app)
        .post('/api/verify')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 when payload is provided without signature', async () => {
      const response = await request(app)
        .post('/api/verify')
        .send({
          payload: samplePayload,
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 when required payload fields are missing', async () => {
      const response = await request(app)
        .post('/api/verify')
        .send({
          payload: {
            institutionId: 'inst-123',
            content: 'Content with missing title',
            issuedAt: '2026-07-01T00:00:00.000Z',
            expiresAt: '2026-12-31T23:59:59.000Z',
          },
          signature: 'dummy_sig',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 when expiresAt is earlier than issuedAt', async () => {
      const response = await request(app)
        .post('/api/verify')
        .send({
          payload: {
            institutionId: 'inst-123',
            title: 'Invalid Date Circular',
            content: 'Content',
            issuedAt: '2026-09-01T00:00:00.000Z',
            expiresAt: '2026-08-01T00:00:00.000Z',
          },
          signature: 'dummy_sig',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });
  });
});
