import { describe, it, expect } from 'vitest';
import { sanitizeHtml } from '../sanitizeHtml';

// vitest runs in jsdom environment allowing DOMPurify to function

describe('sanitizeHtml', () => {
  it('removes script tags', () => {
    const dirty = '<img src=x onerror=alert(1)><script>alert(2)</script>';
    const clean = sanitizeHtml(dirty);
    expect(clean).not.toMatch(/<script/);
    expect(clean).not.toMatch(/onerror/);
  });

  it('preserves safe markup', () => {
    const dirty = '<b>bold</b><i>italic</i>';
    const clean = sanitizeHtml(dirty);
    expect(clean).toBe('<b>bold</b><i>italic</i>');
  });
});
