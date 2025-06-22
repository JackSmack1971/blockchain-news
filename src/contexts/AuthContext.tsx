import React, { createContext, useContext, useState, useEffect } from 'react';
import { getToken, setToken, clearToken } from '@/lib/authToken';

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

const apiCall = async <T>(fn: () => Promise<T>, retries = 1): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    if (retries > 0) {
      return apiCall(fn, retries - 1);
    }
    throw new ApiError((error as Error).message);
  }
};

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
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

  // Initialize auth state from secure token
  useEffect(() => {
    const stored = getToken<User>();
    if (stored) {
      setUser(stored.user);
    }
    setIsLoading(false);
  }, []);

  // Persist token when user state changes
  useEffect(() => {
    if (user) {
      setToken<User>({ user });
    } else {
      clearToken();
    }
  }, [user]);

  const login = async (email: string, password: string): Promise<boolean> => {
    setIsLoading(true);
    try {
      await apiCall(() => new Promise(res => setTimeout(res, 1000)));
      if (!email || !password) {
        throw new ApiError('Missing credentials');
      }
      const mockUser: User = {
        id: '1',
        username: email.split('@')[0],
        email,
        avatar: '/images/avatars/default.jpg',
        bio: 'Blockchain enthusiast and crypto investor',
        preferences: {
          categories: ['Market Analysis', 'DeFi'],
          notifications: true,
          newsletter: true,
        },
        bookmarks: [],
      };
      setUser(mockUser);
      return true;
    } catch (error) {
      console.error('Login error:', error);
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const loginWithWallet = async (walletAddress: string): Promise<boolean> => {
    setIsLoading(true);
    try {
      await apiCall(() => new Promise(res => setTimeout(res, 1500)));
      if (!walletAddress) {
        throw new ApiError('Wallet address required');
      }
      const mockUser: User = {
        id: '2',
        username: `wallet_${walletAddress.slice(0, 6)}`,
        email: '',
        walletAddress,
        avatar: '/images/avatars/wallet.jpg',
        bio: 'Connected via Web3 wallet',
        preferences: {
          categories: ['DeFi', 'Technology Updates'],
          notifications: true,
          newsletter: false,
        },
        bookmarks: [],
      };
      setUser(mockUser);
      return true;
    } catch (error) {
      console.error('Wallet login error:', error);
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (userData: { username: string; email: string; password: string }): Promise<boolean> => {
    setIsLoading(true);
    try {
      await apiCall(() => new Promise(res => setTimeout(res, 1000)));
      if (!userData.username || !userData.email || !userData.password) {
        throw new ApiError('Missing fields');
      }
      const mockUser: User = {
        id: Date.now().toString(),
        username: userData.username,
        email: userData.email,
        avatar: '/images/avatars/default.jpg',
        bio: '',
        preferences: {
          categories: [],
          notifications: true,
          newsletter: true,
        },
        bookmarks: [],
      };
      setUser(mockUser);
      return true;
    } catch (error) {
      console.error('Registration error:', error);
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    clearToken();
    setUser(null);
  };

  const updateProfile = async (updates: Partial<User>): Promise<boolean> => {
    if (!user) return false;
    
    setIsLoading(true);
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));
      
      setUser(prevUser => ({
        ...prevUser!,
        ...updates,
      }));
      return true;
    } catch (error) {
      console.error('Profile update error:', error);
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
