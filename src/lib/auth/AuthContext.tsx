import React, { createContext, useContext, useState } from 'react';
import { apiFetch } from '../api';
import { setToken, clearToken } from '../authToken';
import Web3AuthManager from './Web3AuthManager';
import { sanitizeNonce } from './AuthValidator';

interface Session {
  userId?: string;
  address?: string;
}

interface AuthValue {
  session: Session | null;
  loading: boolean;
  loginWithToken: (token: string) => void;
  loginWithWallet: (nonce: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthValue | null>(null);

const parseJwt = (token: string): any => {
  const payload = token.split('.')[1];
  const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
  const json = decodeURIComponent(
    atob(base64)
      .split('')
      .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join(''),
  );
  return JSON.parse(json);
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const web3 = new Web3AuthManager();
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(false);

  const loginWithToken = (token: string): void => {
    setToken(token);
    const payload = parseJwt(token) as { sub?: string };
    setSession({ userId: payload?.sub });
  };

  const loginWithWallet = async (nonce: string): Promise<void> => {
    setLoading(true);
    try {
      const cleanNonce = sanitizeNonce(nonce);
      const { address } = await web3.connectWallet();
      const signature = await web3.signAuthMessage(cleanNonce, address);
      await apiFetch(`${process.env.API_BASE || ''}/api/web3-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address, signature, nonce: cleanNonce }),
      });
      setSession({ address });
    } finally {
      setLoading(false);
    }
  };

  const logout = (): void => {
    clearToken();
    setSession(null);
  };

  return (
    <AuthContext.Provider value={{ session, loading, loginWithToken, loginWithWallet, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthValue => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('AuthProvider missing');
  return ctx;
};
