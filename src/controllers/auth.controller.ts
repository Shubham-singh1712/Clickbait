import { Request, Response, NextFunction } from 'express';
import { ResponseUtil } from '../utils/api-response';

export class AuthController {
  /**
   * POST /api/auth/login
   * Placeholder controller for institution authentication.
   */
  public async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        ResponseUtil.error(res, 'Email and password are required', 400, 'VALIDATION_ERROR');
        return;
      }

      // Placeholder authentication response for Phase 1 skeleton
      ResponseUtil.success(
        res,
        {
          token: 'jwt_placeholder_token',
          user: {
            id: 'placeholder-institution-admin-id',
            email,
            role: 'INSTITUTION_ADMIN',
          },
        },
        'Authentication successful (Phase 1 skeleton)'
      );
    } catch (error) {
      next(error);
    }
  }
}

export const authController = new AuthController();
