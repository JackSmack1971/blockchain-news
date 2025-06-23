import { describe, it, expect } from 'vitest';
import { sanitizeNonce, sanitizeAddress, sanitizeMessage } from '../auth/AuthValidator';

describe('AuthValidator', () => {
  it('sanitizes nonce', () => {
    expect(sanitizeNonce('abc123!@#')).toBe('abc123');
  });

  it('sanitizes address', () => {
    const addr = ' 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 ';
    expect(sanitizeAddress(addr)).toBe('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045');
    expect(sanitizeAddress('bad')).toBe('');
    expect(sanitizeAddress('0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d0')).toBe('');
  });

  it('sanitizes message html', () => {
    const dirty = '<script>evil()</script>hello';
    expect(sanitizeMessage(dirty)).toBe('hello');
  });
});
