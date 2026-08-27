import { app } from './app';
import { env } from './config/env';
import { connectDatabase, disconnectDatabase } from './config/database';
import { logger } from './utils/logger';

async function startServer(): Promise<void> {
  try {
    // Attempt database connection
    await connectDatabase();

    const server = app.listen(env.PORT, () => {
      logger.info(`=======================================================`, 'Server');
      logger.info(` CLICKBAIT Backend Server is running!`, 'Server');
      logger.info(` Port:        ${env.PORT}`, 'Server');
      logger.info(` Environment: ${env.NODE_ENV}`, 'Server');
      logger.info(` API Prefix:  ${env.API_PREFIX}`, 'Server');
      logger.info(` Health URL:  http://localhost:${env.PORT}${env.API_PREFIX}/health`, 'Server');
      logger.info(`=======================================================`, 'Server');
    });

    // Graceful shutdown handling
    const gracefulShutdown = async (signal: string) => {
      logger.info(`Received ${signal}. Shutting down gracefully...`, 'Server');
      server.close(async () => {
        logger.info('HTTP server closed.', 'Server');
        await disconnectDatabase();
        process.exit(0);
      });

      // Force shutdown if cleanup takes too long
      setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down', undefined, 'Server');
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  } catch (error) {
    logger.error('Fatal error during server startup', error, 'Server');
    process.exit(1);
  }
}

// Start server when executed directly
if (process.env.NODE_ENV !== 'test') {
  startServer();
}
