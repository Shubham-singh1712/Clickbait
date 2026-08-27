import { Router } from 'express';
import { authController } from '../controllers/auth.controller';

const router = Router();

// POST /api/auth/login
router.post('/login', (req, res, next) => authController.login(req, res, next));

export default router;
