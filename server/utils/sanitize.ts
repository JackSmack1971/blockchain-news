import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const window = new JSDOM('').window as unknown as Window;
const DOMPurify = createDOMPurify(window);

/**
 * Sanitize untrusted HTML or text input.
 * Removes script tags, javascript: URLs and event-handler attributes.
 *
 * @param dirty - raw user input
 * @returns cleaned string safe for storage
 */
export const sanitize = (dirty: unknown): string => {
  if (typeof dirty !== 'string') return '';
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'p', 'br'],
    ALLOWED_ATTR: [],
  });
};
