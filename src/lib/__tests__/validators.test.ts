import { describe, it, expect } from 'vitest';
import { loginSchema, registerSchema } from '../validators';

describe('loginSchema', () => {
  it('validates correct data', () => {
    const result = loginSchema.safeParse({ email: 'test@example.com', password: 'abcdef' });
    expect(result.success).toBe(true);
  });

  it('fails on invalid email', () => {
    const result = loginSchema.safeParse({ email: 'bad', password: 'abcdef' });
    expect(result.success).toBe(false);
  });
});

describe('registerSchema', () => {
  it('validates correct data', () => {
    const result = registerSchema.safeParse({
      username: 'user',
      email: 'a@b.com',
      password: 'abcdef',
      confirmPassword: 'abcdef',
    });
    expect(result.success).toBe(true);
  });

  it('fails when passwords do not match', () => {
    const result = registerSchema.safeParse({
      username: 'user',
      email: 'a@b.com',
      password: 'abcdef',
      confirmPassword: 'abc',
    });
    expect(result.success).toBe(false);
  });
});
