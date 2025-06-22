import fs from 'fs/promises';
import { mkdirSync, existsSync, chmodSync, statSync, renameSync } from 'fs';
import path from 'path';

interface LogEntry {
  timestamp: string;
  event: string;
  details: unknown;
}

const LOG_DIR = 'logs';
const LOG_FILE = path.join(LOG_DIR, 'security.log');
const MAX_SIZE = 5 * 1024 * 1024; // 5MB

export const metrics = {
  failedLogin: 0,
  rateLimitViolation: 0,
  headerViolation: 0,
  dbError: 0,
};

function ensureLogDir(): void {
  if (!existsSync(LOG_DIR)) {
    mkdirSync(LOG_DIR, { mode: 0o700 });
  }
}

function rotateIfNeeded(): void {
  if (existsSync(LOG_FILE)) {
    const { size } = statSync(LOG_FILE);
    if (size > MAX_SIZE) {
      const backup = `${LOG_FILE}.${Date.now()}`;
      renameSync(LOG_FILE, backup);
    }
  }
}

function checkAlerts(event: string): void {
  if (event === 'failed_login' && metrics.failedLogin >= 10) {
    console.warn('High number of failed logins');
  }
  if (event === 'rate_limit_exceeded' && metrics.rateLimitViolation >= 5) {
    console.warn('Rate limit exceeded frequently');
  }
}

export async function logSecurityEvent(event: string, details: unknown): Promise<void> {
  ensureLogDir();
  rotateIfNeeded();
  const entry: LogEntry = { timestamp: new Date().toISOString(), event, details };
  const line = JSON.stringify(entry) + '\n';
  try {
    await fs.appendFile(LOG_FILE, line, { mode: 0o600 });
  } catch (err) {
    console.error('security log failure', err);
  }
  if (event === 'failed_login') metrics.failedLogin++;
  if (event === 'rate_limit_exceeded') metrics.rateLimitViolation++;
  if (event === 'header_violation') metrics.headerViolation++;
  if (event === 'db_error') metrics.dbError++;
  checkAlerts(event);
}

export function resetMetrics(): void {
  metrics.failedLogin = 0;
  metrics.rateLimitViolation = 0;
  metrics.headerViolation = 0;
  metrics.dbError = 0;
}
