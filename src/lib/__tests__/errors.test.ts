import { describe, it, expect, vi } from 'vitest';
import { NetworkError, ValidationError, logError } from '../errors';

describe('custom errors', () => {
  it('NetworkError sets name and status', () => {
    const err = new NetworkError('fail', 500);
    expect(err.name).toBe('NetworkError');
    expect(err.status).toBe(500);
  });

  it('ValidationError sets name', () => {
    const err = new ValidationError('bad');
    expect(err.name).toBe('ValidationError');
  });

  it('logError outputs structured JSON', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const error = new Error('boom');
    logError(error, 'test');
    expect(spy).toHaveBeenCalled();
    const arg = spy.mock.calls[0][0] as string;
    const parsed = JSON.parse(arg);
    expect(parsed.context).toBe('test');
    expect(parsed.message).toBe('boom');
    spy.mockRestore();
  });
});
