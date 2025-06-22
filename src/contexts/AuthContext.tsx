import React, { createContext, useContext, useState, useEffect } from 'react';
import { getToken, setToken, clearToken, apiRequest } from '@/lib/authToken';
import { logError } from '@/lib/errors';

interface User {
  id: string;
  username: string;
  email: string;
  avatar?: string;
  bio?: string;
  preferences?: {
    categories: string[];
    notifications: boolean;
    newsletter: boolean;
  };
  bookmarks?: string[];
  walletAddress?: string;
}

class ApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<boolean>;
  loginWithWallet: (walletAddress: string) => Promise<boolean>;
  register: (userData: { username: string; email: string; password: string }) => Promise<boolean>;
  logout: () => void;
  updateProfile: (updates: Partial<User>) => Promise<boolean>;
  addBookmark: (articleId: string) => void;
  removeBookmark: (articleId: string) => void;
  isBookmarked: (articleId: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Initialize auth state from secure token
  useEffect(() => {
    (async () => {
      const stored = await getToken<User>();
      if (stored) {
        setUser(stored.user);
      }
      setIsLoading(false);
    })();
  }, []);

  // Persist token when user state changes
  useEffect(() => {
    (async () => {
      if (user) {
        await setToken<User>({ user });
      } else {
        await clearToken();
      }
    })();
  }, [user]);

  const login = async (email: string, password: string): Promise<boolean> => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiRequest<User>('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      setUser(data);
      return true;
    } catch (error) {
      setError('Unable to login. Please try again.');
      logError(error, 'login');
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const loginWithWallet = async (walletAddress: string): Promise<boolean> => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiRequest<User>('/api/login/wallet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ walletAddress }),
      });
      setUser(data);
      return true;
    } catch (error) {
      setError('Wallet login failed.');
      logError(error, 'loginWithWallet');
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (userData: { username: string; email: string; password: string }): Promise<boolean> => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiRequest<User>('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData),
      });
      setUser(data);
      return true;
    } catch (error) {
      setError('Registration failed.');
      logError(error, 'register');
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setError(null);
    try {
      await apiRequest('/api/logout', { method: 'POST' });
    } catch (error) {
      logError(error, 'logout');
    } finally {
      await clearToken();
      setUser(null);
    }
  };

  const updateProfile = async (updates: Partial<User>): Promise<boolean> => {
    if (!user) return false;

    setIsLoading(true);
    setError(null);
    try {
      await apiRequest('/api/profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      });

      setUser(prevUser => ({
        ...prevUser!,
        ...updates,
      }));
      return true;
    } catch (error) {
      setError('Profile update failed.');
      logError(error, 'updateProfile');
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const addBookmark = (articleId: string) => {
    if (!user) return;
    
    setUser(prevUser => ({
      ...prevUser!,
      bookmarks: [...(prevUser!.bookmarks || []), articleId],
    }));
  };

  const removeBookmark = (articleId: string) => {
    if (!user) return;
    
    setUser(prevUser => ({
      ...prevUser!,
      bookmarks: (prevUser!.bookmarks || []).filter(id => id !== articleId),
    }));
  };

  const isBookmarked = (articleId: string): boolean => {
    if (!user) return false;
    return (user.bookmarks || []).includes(articleId);
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isLoading,
    error,
    login,
    loginWithWallet,
    register,
    logout,
    updateProfile,
    addBookmark,
    removeBookmark,
    isBookmarked,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
