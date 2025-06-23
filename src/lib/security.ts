import DOMPurify from 'dompurify'

/**
 * Sanitizes a user supplied string using DOMPurify in strict mode.
 * All HTML tags and attributes are stripped from the input.
 *
 * @param input - The raw user input.
 * @returns A sanitized string safe for further processing.
 */
export function sanitizeInput(input: string): string {
  return DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }).trim()
}
