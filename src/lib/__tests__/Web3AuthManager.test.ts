import { describe, it, expect, beforeEach, vi } from 'vitest';
import Web3AuthManager from '../auth/Web3AuthManager';

class MockProvider {
  send = vi.fn();
  getSigner = vi.fn().mockResolvedValue({
    getAddress: vi.fn().mockResolvedValue('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'),
    signMessage: vi.fn().mockResolvedValue('0x'.padEnd(132, 'a')),
  });
}

declare global {
  interface Window { ethereum?: unknown; }
}

describe('Web3AuthManager', () => {
  beforeEach(() => {
    window.ethereum = { request: vi.fn() } as any;
  });

  it('connects wallet and returns address', async () => {
    const mgr = new Web3AuthManager(() => new MockProvider() as any);
    const result = await mgr.connectWallet();
    expect(result.address).toBe('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045');
  });

  it('signs authentication message', async () => {
    const mgr = new Web3AuthManager(() => new MockProvider() as any);
    const sig = await mgr.signAuthMessage('nonce', '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045');
    expect(sig).toMatch(/^0x/);
  });
});
