import { describe, it, expect } from 'vitest';
import {
  loginSchema,
  registerSchema,
  ethereumAddressSchema,
  walletLoginSchema,
  validateInput,
  validationRules,
} from '../validators';

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

describe('ethereumAddressSchema', () => {
  it('accepts valid checksum address', () => {
    const result = ethereumAddressSchema.safeParse(
      '0x52908400098527886E0F7030069857D2E4169EE7',
    );
    expect(result.success).toBe(true);
  });

  it('rejects invalid format', () => {
    const result = ethereumAddressSchema.safeParse('0x12345');
    expect(result.success).toBe(false);
  });

  it('rejects bad checksum', () => {
    const result = ethereumAddressSchema.safeParse(
      '0x52908400098527886E0F7030069857d2E4169EE7',
    );
    expect(result.success).toBe(false);
  });
});

describe('walletLoginSchema', () => {
  it('requires walletAddress and signature', () => {
    const result = walletLoginSchema.safeParse({ walletAddress: '0x52908400098527886E0F7030069857D2E4169EE7' });
    expect(result.success).toBe(false);
  });
});

describe('validateInput', () => {
  it('rejects XSS payload', () => {
    const res = validateInput('<script>alert(1)</script>', validationRules.username);
    expect(res.isValid).toBe(false);
  });

  it('sanitizes valid input', () => {
    const res = validateInput('  Alice  ', validationRules.username);
    expect(res.isValid).toBe(true);
    expect(res.value).toBe('alice');
  });
});
