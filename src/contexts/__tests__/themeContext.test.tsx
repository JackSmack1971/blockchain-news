import { describe, it, expect, beforeAll } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/react';
import React from 'react';
import { ThemeProvider, useThemeContext } from '../ThemeContext';

const TestComponent = () => {
  const { theme, toggleTheme } = useThemeContext();
  return (
    <button onClick={toggleTheme} data-testid="btn">
      {theme}
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
});
