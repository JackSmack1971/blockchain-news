import { z } from 'zod';

export const environmentSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().regex(/^\d+$/).transform(Number).default('3000'),
  SESSION_SECRET: z
    .string()
    .min(32, 'Session secret must be at least 32 characters'),
  DATABASE_URL: z.string().url().optional(),
  DB_HOST: z.string().optional(),
  DB_PORT: z.string().regex(/^\d+$/).transform(Number).optional(),
  DB_NAME: z.string().optional(),
  DB_USER: z.string().optional(),
  DB_PASSWORD: z.string().optional(),
  COOKIE_DOMAIN: z.string().regex(/^[a-zA-Z0-9.-]+$/).optional(),
  COOKIE_MAX_AGE: z
    .string()
    .regex(/^\d+$/)
    .transform(Number)
    .default('86400000'),
  COOKIE_SECURE: z.string().transform((val) => val === 'true').default('false'),
  RATE_LIMIT_WINDOW: z
    .string()
    .regex(/^\d+$/)
    .transform(Number)
    .default('900000'),
  RATE_LIMIT_MAX: z.string().regex(/^\d+$/).transform(Number).default('5'),
  FRONTEND_URL: z.string().url().default('http://localhost:3000'),
  REDIS_URL: z.string().url().optional(),
  SIGNIN_DOMAIN: z.string().min(1),
  SIGNIN_CHAIN_ID: z.string().regex(/^\d+$/).transform(Number),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
});

export type Environment = z.infer<typeof environmentSchema>;

export interface EnvResultSuccess {
  success: true;
  data: Environment;
}

export interface EnvResultFailure {
  success: false;
  error: string;
}

export type EnvResult = EnvResultSuccess | EnvResultFailure;

/**
 * Validate environment variables using predefined schema.
 * @param env process environment or partial substitute
 * @returns validation result with typed data or error message
 */
export const validateEnvironment = (env: NodeJS.ProcessEnv = process.env): EnvResult => {
  try {
    const data = environmentSchema.parse(env);
    return { success: true, data };
  } catch (err) {
    return {
      success: false,
      error: `Environment validation failed: ${(err as Error).message}`,
    };
  }
};

