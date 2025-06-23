import crypto from 'crypto';

/**
 * Generate a cryptographically secure session secret.
 * This should be used when creating production SESSION_SECRET values.
 *
 * @returns 64-character hexadecimal secret string
 */
export function generateSessionSecret(): string {
  return crypto.randomBytes(32).toString('hex');
}
