import { Request, Response, NextFunction } from 'express';
import { ResponseUtil } from '../utils/api-response';
import { logger } from '../utils/logger';

export function errorHandler(
  err: Error | any,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  const statusCode = err.statusCode || err.status || 500;
  const message = err.message || 'Internal server error';
  const code = err.code || 'INTERNAL_SERVER_ERROR';

  logger.error(`Error processing request ${req.method} ${req.originalUrl}: ${message}`, err, 'ErrorHandler');

  ResponseUtil.error(
    res,
    message,
    statusCode,
    code,
    process.env.NODE_ENV === 'development' ? { stack: err.stack } : undefined
  );
}
