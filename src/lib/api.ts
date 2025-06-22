export interface FetchOptions {
  retries?: number;
  timeout?: number;
}

import { NetworkError } from './errors';

export const apiFetch = async <T>(
  input: RequestInfo | URL,
  init: RequestInit = {},
  options: FetchOptions = {},
): Promise<T> => {
  const { retries = 1, timeout = 5000 } = options;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(input, { ...init, signal: controller.signal });
    clearTimeout(id);
    if (!response.ok) {
      throw new NetworkError(`HTTP ${response.status}`, response.status);
    }
    return (await response.json()) as T;
  } catch (error) {
    clearTimeout(id);
    if (retries > 0) {
      return apiFetch<T>(input, init, { retries: retries - 1, timeout });
    }
    throw new NetworkError((error as Error).message);
  }
};
