import dotenv from 'dotenv';
import { validateEnvironment } from './config/environment';

dotenv.config();

const envResult = validateEnvironment();
if (!envResult.success) {
  throw new Error(envResult.error);
}

const envConfig = envResult.data;
const secret = process.env.SESSION_SECRET;
if (!secret || secret.length < 32) {
  throw new Error('SESSION_SECRET must be at least 32 characters of cryptographic randomness');
}

export const config = { ...envConfig, SESSION_SECRET: secret };
