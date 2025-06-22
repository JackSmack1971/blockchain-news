import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import BlockchainNewsInterface from '../BlockchainNewsInterface';

describe('BlockchainNewsInterface', () => {
  it('renders crypto ticker entries', () => {
    render(<BlockchainNewsInterface />);
    expect(screen.getAllByText(/BTC|ETH|BNB/).length).toBeGreaterThan(0);
  });
});
