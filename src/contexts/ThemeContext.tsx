import React, {
  createContext,
  useContext,
  useEffect,
  useState,
} from 'react';

export type Theme = 'light' | 'dark' | 'system';

interface ThemeContextType {
  theme: Theme;
  resolvedTheme: 'light' | 'dark';
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
}

class ThemeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ThemeError';
  }
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const useThemeContext = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new ThemeError('useThemeContext must be used within a ThemeProvider');
  }
  return context;
};

const storageKey = 'theme';

const getStoredTheme = (): Theme => {
  try {
    const value = localStorage.getItem(storageKey);
    if (value === 'light' || value === 'dark' || value === 'system') {
      return value;
    }
  } catch (_) {
    /* ignore */
  }
  return 'system';
};

const systemPrefersDark = () =>
  window.matchMedia('(prefers-color-scheme: dark)').matches;

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [theme, setThemeState] = useState<Theme>(() =>
    typeof window === 'undefined' ? 'system' : getStoredTheme(),
  );
  const [resolvedTheme, setResolvedTheme] = useState<'light' | 'dark'>(() =>
    theme === 'system' ? (systemPrefersDark() ? 'dark' : 'light') : theme,
  );

  useEffect(() => {
    const mql = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => {
      if (theme === 'system') {
        setResolvedTheme(mql.matches ? 'dark' : 'light');
      }
    };
    onChange();
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, [theme]);

  useEffect(() => {
    try {
      if (theme === 'system') {
        localStorage.removeItem(storageKey);
      } else {
        localStorage.setItem(storageKey, theme);
      }
    } catch (_) {
      /* ignore */
    }
  }, [theme]);

  useEffect(() => {
    const root = document.documentElement;
    if (resolvedTheme === 'dark') root.classList.add('dark');
    else root.classList.remove('dark');
  }, [resolvedTheme]);

  const setTheme = (t: Theme) => {
    setThemeState(t);
    if (t === 'light' || t === 'dark') {
      setResolvedTheme(t);
    } else {
      setResolvedTheme(systemPrefersDark() ? 'dark' : 'light');
    }
  };

  const toggleTheme = () =>
    setThemeState((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      setResolvedTheme(next);
      return next;
    });

  const value = {
    theme,
    resolvedTheme,
    setTheme,
    toggleTheme,
  } as ThemeContextType;

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};
