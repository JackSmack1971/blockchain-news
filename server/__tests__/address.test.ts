import { describe, it, expect } from 'vitest';
import { validateEthereumAddress } from '../utils/address';

describe('validateEthereumAddress', () => {
  it('accepts valid addresses', () => {
    const res = validateEthereumAddress('0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d0');
    expect(res.valid).toBe(true);
    expect(res.address).toBe('0x742d35Cc6634C0532925a3b8D2B7D17a33b6C4d0');
  });

  it('rejects malformed addresses', () => {
    const res = validateEthereumAddress('0x123');
    expect(res.valid).toBe(false);
  });

  it('rejects bad checksum', () => {
    const res = validateEthereumAddress('0x742d35cc6634c0532925a3b8d2b7d17a33b6c4d0');
    expect(res.valid).toBe(false);
  });
});
