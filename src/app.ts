import express, { Application } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import routes from './routes';
import { env } from './config/env';
import { requestLogger } from './middleware/request-logger.middleware';
import { notFoundHandler } from './middleware/not-found.middleware';
import { errorHandler } from './middleware/error.middleware';

export function createApp(): Application {
  const app: Application = express();

  // Security headers
  app.use(helmet());

  // CORS configuration
  app.use(
    cors({
      origin: env.CORS_ORIGIN === '*' ? '*' : env.CORS_ORIGIN.split(','),
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    })
  );

  // Request body parsing
  app.use(express.json({ limit: '10mb' })); // Allows base64 screenshot uploads
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request logging
  app.use(requestLogger);

  // Mount API router
  app.use(env.API_PREFIX, routes);

  // Root fallback
  app.get('/', (_req, res) => {
    res.json({
      name: 'CLICKBAIT Backend API',
      version: '0.1.0',
      description: "Don't Guess. Verify. - SIH 2026",
      documentation: '/api/health',
    });
  });

  // 404 handler
  app.use(notFoundHandler);

  // Global error handler
  app.use(errorHandler);

  return app;
}

export const app = createApp();
