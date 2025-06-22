import DOMPurify from 'dompurify';

/**
 * Sanitize HTML to prevent XSS attacks before rendering.
 *
 * @param dirty - Untrusted HTML string supplied by users.
 * @returns Sanitized HTML safe for rendering with `dangerouslySetInnerHTML`.
 */
export const sanitizeHtml = (dirty: string): string => {
  return DOMPurify.sanitize(dirty, { USE_PROFILES: { html: true } });
};
