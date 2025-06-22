import { describe, it, expect } from 'vitest';
import { validateEnvironment } from '../config/environment';

describe('Environment Configuration', () => {
  it('should reject short session secret', () => {
    const result = validateEnvironment({ SESSION_SECRET: 'short' } as NodeJS.ProcessEnv);
    expect(result.success).toBe(false);
    expect(result.error).toContain('Session secret');
  });

  it('should accept valid configuration', () => {
    const env = {
      SESSION_SECRET: 'a-very-long-and-secure-session-secret-key',
      PORT: '3000',
    } as NodeJS.ProcessEnv;
    const result = validateEnvironment(env);
    expect(result.success).toBe(true);
  });
});
