import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { AuthProvider, useAuth } from '../../contexts/AuthContext';

vi.mock('../api', () => ({ apiFetch: vi.fn().mockResolvedValue({}) }));
vi.mock('../auth/Web3AuthManager', () => {
  return {
    default: vi.fn().mockImplementation(() => ({
      connectWallet: vi.fn().mockResolvedValue({
        address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
        signer: {},
      }),
      signAuthMessage: vi.fn().mockResolvedValue({
        message: 'msg',
        signature: '0x'.padEnd(132, 'a'),
      }),
    })),
  };
});

describe('AuthContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('login sets session', async () => {
    const mockResponse = { token: 't', user: { id: '1', username: 'u', email: 'e' } };
    const { apiFetch } = await import('../api');
    (apiFetch as any).mockResolvedValueOnce(mockResponse);
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await act(async () => {
      await result.current.login('e', 'p');
    });
    expect(result.current.user?.id).toBe('1');
  });

  it('loginWithWallet signs message and calls API', async () => {
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    const { apiFetch } = await import('../api');
    await act(async () => {
      await result.current.loginWithWallet('nonce');
    });
    expect((apiFetch as any).mock.calls[0][0]).toBe('/api/login/wallet');
    const body = JSON.parse((apiFetch as any).mock.calls[0][1].body);
    expect(body).toEqual({ message: 'msg', signature: '0x'.padEnd(132, 'a') });
  });
});
