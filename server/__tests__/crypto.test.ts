import { describe, it, expect } from 'vitest';
import { generateSessionSecret } from '../utils/crypto';

describe('generateSessionSecret', () => {
  it('returns a 64-character hexadecimal string', () => {
    const secret = generateSessionSecret();
    expect(secret).toMatch(/^[a-f0-9]{64}$/i);
  });

  it('generates unique secrets', () => {
    const first = generateSessionSecret();
    const second = generateSessionSecret();
    expect(first).not.toBe(second);
  });
});
