import { Router } from 'express';
import { noticeController } from '../controllers/notice.controller';

const router = Router();

// POST /api/notices
router.post('/', (req, res, next) => noticeController.createNotice(req, res, next));

// POST /api/notices/:id/revoke
router.post('/:id/revoke', (req, res, next) => noticeController.revokeNotice(req, res, next));

export default router;
