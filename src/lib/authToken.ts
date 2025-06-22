import type { RequestInit } from 'undici';

export interface TokenPayload<T = unknown> {
  user: T;
}

const TOKEN_ENDPOINT = '/api/token';

class TokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenError';
  }
}

/**
 * Perform a fetch request with timeout and retry logic.
 */
const apiRequest = async <T>(
  input: RequestInfo | URL,
  init: RequestInit = {},
  retries = 1,
  timeout = 5000,
): Promise<T> => {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(input, {
      ...init,
      signal: controller.signal,
      credentials: 'include',
    } as RequestInit);
    clearTimeout(id);
    if (!response.ok) {
      throw new TokenError(`HTTP ${response.status}`);
    }
    return (await response.json()) as T;
  } catch (error) {
    clearTimeout(id);
    if (retries > 0) {
      return apiRequest<T>(input, init, retries - 1, timeout);
    }
    throw new TokenError((error as Error).message);
  }
};

/**
 * Send payload to server for JWT signing and httpOnly cookie storage.
 */
export const setToken = async <T>(payload: TokenPayload<T>): Promise<void> => {
  await apiRequest<void>(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
};

/**
 * Retrieve and verify JWT from secure cookie via server call.
 */
export const getToken = async <T>(): Promise<TokenPayload<T> | null> => {
  try {
    return await apiRequest<TokenPayload<T>>(TOKEN_ENDPOINT);
  } catch {
    return null;
  }
};

/**
 * Clear authentication token cookie on the server.
 */
export const clearToken = async (): Promise<void> => {
  await apiRequest<void>(TOKEN_ENDPOINT, { method: 'DELETE' });
};
