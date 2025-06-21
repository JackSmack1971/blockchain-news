import React, { createContext, useContext, useState, useEffect } from 'react';

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

  // Initialize auth state from localStorage
  useEffect(() => {
    const savedUser = localStorage.getItem('blockchain-news-user');
    if (savedUser) {
      try {
        setUser(JSON.parse(savedUser));
      } catch (error) {
        console.error('Error parsing saved user:', error);
        localStorage.removeItem('blockchain-news-user');
      }
    }
    setIsLoading(false);
  }, []);

  // Save user to localStorage whenever user state changes
  useEffect(() => {
    if (user) {
      localStorage.setItem('blockchain-news-user', JSON.stringify(user));
    } else {
      localStorage.removeItem('blockchain-news-user');
    }
  }, [user]);

  const login = async (email: string, password: string): Promise<boolean> => {
    setIsLoading(true);
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Mock successful login
      if (email && password) {
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
      }
      return false;
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
      // Simulate wallet connection
      await new Promise(resolve => setTimeout(resolve, 1500));
      
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
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      
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
