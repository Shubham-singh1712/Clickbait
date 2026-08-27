import { Router } from 'express';
import authRoutes from './auth.routes';
import institutionRoutes from './institution.routes';
import noticeRoutes from './notice.routes';
import verificationRoutes from './verification.routes';
import { ResponseUtil } from '../utils/api-response';

const router = Router();

// Health check endpoint
router.get('/health', (_req, res) => {
  ResponseUtil.success(
    res,
    {
      status: 'UP',
      service: 'clickbait-backend',
      environment: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
    },
    'CLICKBAIT Backend API is operational'
  );
});

// Mount domain routes
router.use('/auth', authRoutes);
router.use('/institutions', institutionRoutes);
router.use('/notices', noticeRoutes);
router.use('/verify', verificationRoutes);

export default router;
