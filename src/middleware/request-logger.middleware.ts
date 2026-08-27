import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();
  const { method, originalUrl, ip } = req;

  res.on('finish', () => {
    const duration = Date.now() - start;
    const { statusCode } = res;
    const logMessage = `${method} ${originalUrl} ${statusCode} - ${duration}ms [IP: ${ip}]`;

    if (statusCode >= 500) {
      logger.error(logMessage, undefined, 'HTTP');
    } else if (statusCode >= 400) {
      logger.warn(logMessage, 'HTTP');
    } else {
      logger.info(logMessage, 'HTTP');
    }
  });

  next();
}
