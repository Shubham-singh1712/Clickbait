import request from 'supertest';
import { app } from '../../src/app';

describe('Notice Creation & Signing API Integration Tests (Phase 5)', () => {
  const validNoticePayload = {
    institutionId: 'inst-iit-delhi-01',
    title: 'Autumn Semester 2026 Academic Calendar',
    content: 'All classes will commence on August 1, 2026. Registration deadline is July 25, 2026.',
    issuedAt: '2026-07-01T00:00:00.000Z',
    expiresAt: '2026-12-31T23:59:59.000Z',
  };

  describe('POST /api/notices', () => {
    it('should create and sign a new notice returning cryptographic metadata', async () => {
      const response = await request(app)
        .post('/api/notices')
        .send(validNoticePayload);

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
      expect(response.body.data.institutionId).toBe(validNoticePayload.institutionId);
      expect(response.body.data.title).toBe(validNoticePayload.title);
      expect(response.body.data.content).toBe(validNoticePayload.content);
      expect(response.body.data).toHaveProperty('contentHash');
      expect(response.body.data).toHaveProperty('signature');
      expect(response.body.data.status).toBe('ACTIVE');

      // Security check: Private keys must never be returned in API response
      expect(response.body.data.privateKey).toBeUndefined();
      expect(response.body.data.privateKeyBase64).toBeUndefined();
      expect(response.body.data.secret).toBeUndefined();
    });

    it('should return 400 when required fields are missing', async () => {
      const missingTitle = {
        institutionId: 'inst-123',
        content: 'Some content',
        expiresAt: '2026-12-31T23:59:59.000Z',
      };

      const response = await request(app)
        .post('/api/notices')
        .send(missingTitle);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 when expiresAt is earlier than issuedAt', async () => {
      const invalidDates = {
        institutionId: 'inst-123',
        title: 'Invalid Date Circular',
        content: 'Content',
        issuedAt: '2026-09-01T00:00:00.000Z',
        expiresAt: '2026-08-01T00:00:00.000Z',
      };

      const response = await request(app)
        .post('/api/notices')
        .send(invalidDates);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 when title is empty string', async () => {
      const response = await request(app)
        .post('/api/notices')
        .send({
          institutionId: 'inst-123',
          title: '   ',
          content: 'Some content',
          expiresAt: '2026-12-31T23:59:59.000Z',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });

    it('should return 400 when content is empty string', async () => {
      const response = await request(app)
        .post('/api/notices')
        .send({
          institutionId: 'inst-123',
          title: 'Valid Title',
          content: '',
          expiresAt: '2026-12-31T23:59:59.000Z',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });
});
