import { describe, it, expect } from 'vitest';
import { sanitize } from '../utils/sanitize';

describe('sanitize utility', () => {
  it('removes script tags', () => {
    const dirty = '<div>test<script>alert(1)</script></div>';
    const clean = sanitize(dirty);
    expect(clean).not.toMatch(/<script/i);
  });

  it('strips javascript urls', () => {
    const dirty = '<a href="javascript:alert(1)">x</a>';
    const clean = sanitize(dirty);
    expect(clean).not.toMatch(/javascript:/i);
  });

  it('removes event handlers', () => {
    const dirty = '<img src="x" onerror="alert(1)">';
    const clean = sanitize(dirty);
    expect(clean).not.toMatch(/onerror/i);
  });

  it('preserves safe markup', () => {
    const dirty = '<p>Hello <strong>world</strong></p>';
    const clean = sanitize(dirty);
    expect(clean).toBe('<p>Hello <strong>world</strong></p>');
  });
});
