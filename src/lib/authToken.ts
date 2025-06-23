import { apiFetch } from './api';
import SecureTokenManager from './auth/SecureTokenManager';

class TokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenError';
  }
}

/**
 * Perform a fetch request with timeout and retry logic.
 */
export const apiRequest = async <T>(
  input: RequestInfo | URL,
  init: RequestInit = {},
  retries = 1,
  timeout = 5000,
): Promise<T> => {
  try {
    return await apiFetch<T>(input, { ...init, credentials: 'include' }, {
      retries,
      timeout,
    });
  } catch (error) {
    throw new TokenError((error as Error).message);
  }
};

/**
 * Store authentication tokens in memory.
 */
export const setToken = (token: string, refreshToken?: string): void => {
  SecureTokenManager.getInstance().setTokens(token, refreshToken);
};

/**
 * Retrieve the stored access token if still valid.
 */
export const getToken = (): string | null => {
  return SecureTokenManager.getInstance().getToken();
};

/**
 * Remove all stored authentication tokens.
 */
export const clearToken = (): void => {
  SecureTokenManager.getInstance().clearTokens();
};
