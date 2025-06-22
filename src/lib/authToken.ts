import Cookies from 'js-cookie';

export interface TokenPayload<T = unknown> {
  user: T;
}

const TOKEN_KEY = 'auth_token';

export const setToken = <T>(payload: TokenPayload<T>): void => {
  try {
    const encoded = btoa(JSON.stringify(payload));
    const secure = typeof window !== 'undefined' && window.location.protocol === 'https:';
    Cookies.set(TOKEN_KEY, encoded, { secure, sameSite: 'strict' });
  } catch {
    // ignore serialization errors
  }
};

export const getToken = <T>(): TokenPayload<T> | null => {
  const token = Cookies.get(TOKEN_KEY);
  if (!token) return null;
  try {
    return JSON.parse(atob(token)) as TokenPayload<T>;
  } catch {
    return null;
  }
};

export const clearToken = (): void => {
  Cookies.remove(TOKEN_KEY);
};
