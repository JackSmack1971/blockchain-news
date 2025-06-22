import { describe, it, expect } from 'vitest';
import { loginSchema, registerSchema } from '../validators';

describe('loginSchema', () => {
  it('validates correct data', () => {
    const result = loginSchema.safeParse({ email: 'test@example.com', password: 'Abcdef1!' });
    expect(result.success).toBe(true);
  });

  it('fails on invalid email', () => {
    const result = loginSchema.safeParse({ email: 'bad', password: 'Abcdef1!' });
    expect(result.success).toBe(false);
  });

  it('fails on weak password', () => {
    const result = loginSchema.safeParse({ email: 'test@example.com', password: 'abcdef' });
    expect(result.success).toBe(false);
  });
});

describe('registerSchema', () => {
  it('validates correct data', () => {
    const result = registerSchema.safeParse({
      username: 'valid_user',
      email: 'a@b.com',
      password: 'Abcdef1!',
      confirmPassword: 'Abcdef1!',
    });
    expect(result.success).toBe(true);
  });

  it('fails when passwords do not match', () => {
    const result = registerSchema.safeParse({
      username: 'valid_user',
      email: 'a@b.com',
      password: 'Abcdef1!',
      confirmPassword: 'Abcdef2!',
    });
    expect(result.success).toBe(false);
  });

  it('fails on invalid username', () => {
    const result = registerSchema.safeParse({
      username: 'bad user!',
      email: 'a@b.com',
      password: 'Abcdef1!',
      confirmPassword: 'Abcdef1!',
    });
    expect(result.success).toBe(false);
  });

  it('fails on weak password', () => {
    const result = registerSchema.safeParse({
      username: 'valid_user',
      email: 'a@b.com',
      password: 'abcdef',
      confirmPassword: 'abcdef',
    });
    expect(result.success).toBe(false);
  });
});

it('fails when email missing', () => {
  const result = loginSchema.safeParse({ password: 'Abcdef1!' });
  expect(result.success).toBe(false);
});

it('fails on short username', () => {
  const result = registerSchema.safeParse({
    username: 'a',
    email: 'a@b.com',
    password: 'Abcdef1!',
    confirmPassword: 'Abcdef1!',
  });
  expect(result.success).toBe(false);
});
