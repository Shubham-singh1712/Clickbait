import dotenv from 'dotenv';
import path from 'path';
import { z } from 'zod';

// Load environment variables from .env if present
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.string().transform((val) => parseInt(val, 10)).default('5000'),
  API_PREFIX: z.string().default('/api'),
  DATABASE_URL: z.string().default('postgresql://postgres:postgres@localhost:5432/clickbait_db?schema=public'),
  CORS_ORIGIN: z.string().default('*'),
  JWT_SECRET: z.string().default('clickbait-development-secret-key-change-in-production'),
  JWT_EXPIRES_IN: z.string().default('7d'),
  BLOCKCHAIN_PROVIDER: z.enum(['mock', 'ethereum', 'polygon', 'hyperledger']).default('mock'),
  BLOCKCHAIN_RPC_URL: z.string().optional().default(''),
  BLOCKCHAIN_CONTRACT_ADDRESS: z.string().optional().default(''),
  AI_RISK_ENGINE_URL: z.string().default('http://localhost:8000/api/analyze'),
  AI_RISK_ENGINE_API_KEY: z.string().optional().default(''),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'http', 'debug']).default('info'),
});

const parsedEnv = envSchema.safeParse(process.env);

if (!parsedEnv.success) {
  console.error('❌ Invalid environment variables configuration:', parsedEnv.error.format());
  throw new Error('Environment variable validation failed');
}

export const env = parsedEnv.data;
