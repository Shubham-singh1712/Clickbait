import request from 'supertest';
import { app } from '../../src/app';

describe('API Route Skeleton Integration Tests (Phase 1)', () => {
  describe('GET /api/health', () => {
    it('should return 200 and operational health status', async () => {
      const response = await request(app).get('/api/health');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.status).toBe('UP');
      expect(response.body.data.service).toBe('clickbait-backend');
    });
  });

  describe('POST /api/auth/login', () => {
    it('should authenticate user with valid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'admin@university.edu',
          password: 'securePassword123!',
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('token');
      expect(response.body.data.user.email).toBe('admin@university.edu');
    });

    it('should return 400 when email or password is missing', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({ email: 'admin@university.edu' });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('POST /api/institutions', () => {
    it('should create a new institution skeleton record', async () => {
      const response = await request(app)
        .post('/api/institutions')
        .send({
          name: 'National Technical University',
          verifiedDomain: 'ntu.edu.in',
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data.name).toBe('National Technical University');
      expect(response.body.data.verifiedDomain).toBe('ntu.edu.in');
      expect(response.body.data.status).toBe('PENDING');
    });

    it('should return 400 if required fields are missing', async () => {
      const response = await request(app)
        .post('/api/institutions')
        .send({ name: 'Incomplete University' });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/notices', () => {
    it('should create and sign a new notice', async () => {
      const response = await request(app)
        .post('/api/notices')
        .send({
          institutionId: 'inst-123',
          title: 'Official Holiday Announcement',
          content: 'The campus will remain closed on Friday for University Day.',
          expiresAt: '2026-12-31T23:59:59.000Z',
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('contentHash');
      expect(response.body.data).toHaveProperty('signature');
      expect(response.body.data.status).toBe('ACTIVE');
    });

    it('should return 400 when missing required notice fields', async () => {
      const response = await request(app)
        .post('/api/notices')
        .send({ title: 'Missing fields' });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/notices/:id/revoke', () => {
    it('should revoke an existing notice with reason', async () => {
      const response = await request(app)
        .post('/api/notices/notice-abc-123/revoke')
        .send({
          reason: 'Erroneous date specified in original circular',
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.status).toBe('REVOKED');
      expect(response.body.data.revocationReason).toBe('Erroneous date specified in original circular');
    });

    it('should return 400 if reason is omitted', async () => {
      const response = await request(app)
        .post('/api/notices/notice-abc-123/revoke')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/verify', () => {
    it('should execute cryptographic verification on payload', async () => {
      const response = await request(app)
        .post('/api/verify')
        .send({
          noticeId: 'notice-abc-123',
          contentHash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
          signature: 'dummy_sig_123',
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.isAuthentic).toBe(true);
      expect(response.body.data.resultStatus).toBe('VERIFIED');
      expect(response.body.data.checks.signatureValid).toBe(true);
      expect(response.body.data.checks.notExpired).toBe(true);
    });
  });

  describe('POST /api/verify/screenshot', () => {
    it('should accept screenshot payload for secondary OCR/AI assessment', async () => {
      const response = await request(app)
        .post('/api/verify/screenshot')
        .send({
          imageDataBase64: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
          claimedDomain: 'university.edu',
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('securityAnalysis');
      expect(response.body.data.securityAnalysis).toHaveProperty('aiAssessment');
    });
  });

  describe('404 Not Found Handler', () => {
    it('should return standard 404 JSON for non-existent routes', async () => {
      const response = await request(app).get('/api/unknown-endpoint');

      expect(response.status).toBe(404);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('ROUTE_NOT_FOUND');
    });
  });
});
