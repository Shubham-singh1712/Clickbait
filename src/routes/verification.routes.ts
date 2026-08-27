import { Router } from 'express';
import { verificationController } from '../controllers/verification.controller';

const router = Router();

// POST /api/verify
router.post('/', (req, res, next) => verificationController.verifyNotice(req, res, next));

// POST /api/verify/screenshot
router.post('/screenshot', (req, res, next) => verificationController.verifyScreenshot(req, res, next));

export default router;
