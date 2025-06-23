import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { AuthProvider, useAuth } from '../auth/AuthContext';

vi.mock('../api', () => ({ apiFetch: vi.fn().mockResolvedValue({}) }));
vi.mock('../auth/Web3AuthManager', () => {
  return {
    default: vi.fn().mockImplementation(() => ({
      connectWallet: vi.fn().mockResolvedValue({
        address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
        signer: {},
      }),
      signAuthMessage: vi.fn().mockResolvedValue('0x'.padEnd(132, 'a')),
    })),
  };
});

describe('AuthContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('loginWithToken sets session', () => {
    const token = 'eyJhbGciOiJIUzI1NiJ9.' +
      btoa(JSON.stringify({ sub: '1', exp: Math.floor(Date.now() / 1000) + 60 }));
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    act(() => result.current.loginWithToken(token));
    expect(result.current.session?.userId).toBe('1');
  });

  it('loginWithWallet sets session address', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await act(async () => {
      await result.current.loginWithWallet('nonce');
    });
    expect(result.current.session?.address).toMatch(/^0x/);
  });
});
