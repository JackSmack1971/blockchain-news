import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { render, fireEvent, screen, cleanup } from '@testing-library/react';
import React from 'react';
import { ThemeProvider, useThemeContext } from '../ThemeContext';

const TestComponent = () => {
  const { theme, resolvedTheme, toggleTheme } = useThemeContext();
  return (
    <button onClick={toggleTheme} data-testid="btn">
      {theme}:{resolvedTheme}
    </button>
  );
};

describe('ThemeContext', () => {
  beforeAll(() => {
    if (!window.matchMedia) {
      window.matchMedia = () => ({
        matches: false,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as unknown as MediaQueryList;
    }
  });
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.classList.remove('dark');
    cleanup();
  });
  it('toggles between light and dark', () => {
    render(
      <ThemeProvider>
        <TestComponent />
      </ThemeProvider>,
    );
    const btn = screen.getByTestId('btn');
    const initial = btn.textContent;
    fireEvent.click(btn);
    expect(btn.textContent).not.toBe(initial);
  });

  it('initializes from storage', () => {
    localStorage.setItem('theme', 'dark');
    render(
      <ThemeProvider>
        <TestComponent />
      </ThemeProvider>,
    );
    const btn = screen.getByTestId('btn');
    expect(btn.textContent?.startsWith('dark')).toBe(true);
  });

  it('applies class to document', () => {
    render(
      <ThemeProvider>
        <TestComponent />
      </ThemeProvider>,
    );
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    fireEvent.click(screen.getByTestId('btn'));
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });
});
