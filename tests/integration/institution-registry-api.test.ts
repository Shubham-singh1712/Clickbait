import request from 'supertest';
import { app } from '../../src/app';
import { ed25519Service } from '../../src/services/crypto/ed25519.service';
import { issuerRegistryService } from '../../src/services/registry/issuer-registry.service';

describe('Institution & Key Registry API Integration Tests (Phase 4)', () => {
  let testKeyPair: { publicKeyBase64: string; privateKeyBase64: string };
  const futureExpiry = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString();

  beforeEach(() => {
    testKeyPair = ed25519Service.generateKeyPair();
  });

  describe('POST /api/institutions/:id/keys', () => {
    it('should return 400 when publicKey or expiresAt is missing', async () => {
      const response = await request(app)
        .post('/api/institutions/inst-test-123/keys')
        .send({ publicKey: testKeyPair.publicKeyBase64 });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 when public key is malformed Base64', async () => {
      const response = await request(app)
        .post('/api/institutions/inst-test-123/keys')
        .send({
          publicKey: 'not-a-valid-base64!',
          expiresAt: futureExpiry,
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    it('should return 400 when public key has invalid byte length', async () => {
      const invalidLengthKey = Buffer.alloc(16, 0x01).toString('base64');
      const response = await request(app)
        .post('/api/institutions/inst-test-123/keys')
        .send({
          publicKey: invalidLengthKey,
          expiresAt: futureExpiry,
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /api/institutions/:id/keys/active', () => {
    it('should return 404 when no active key exists for the institution', async () => {
      const response = await request(app).get('/api/institutions/inst-unknown-999/keys/active');

      expect(response.status).toBe(404);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('KEY_NOT_FOUND');
    });
  });
});
