import { Request, Response, NextFunction } from 'express';
import { ResponseUtil } from '../utils/api-response';

export function notFoundHandler(req: Request, res: Response, _next: NextFunction): void {
  ResponseUtil.error(
    res,
    `Route not found: ${req.method} ${req.originalUrl}`,
    404,
    'ROUTE_NOT_FOUND'
  );
}
