import { describe, it, expect } from 'vitest';
import {
  ethereumAddressSchema,
  walletLoginSchema,
} from '../validators';
import {
  loginSchema,
  registerSchema,
  profileUpdateSchema,
  commentSchema,
  searchSchema,
} from '../validation';

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

  it('rejects script content', () => {
    const result = loginSchema.safeParse({ email: '<script>alert(1)</script>', password: 'Abcdef1!' });
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

  it('rejects dangerous username', () => {
    const result = registerSchema.safeParse({
      username: '<script>alert(1)</script>',
      email: 'a@b.com',
      password: 'Abcdef1!',
      confirmPassword: 'Abcdef1!',
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

  it('rejects dangerous content', () => {
    const result = ethereumAddressSchema.safeParse('javascript:alert(1)');
    expect(result.success).toBe(false);
  });
});

describe('walletLoginSchema', () => {
  it('requires walletAddress and signature', () => {
    const result = walletLoginSchema.safeParse({ walletAddress: '0x52908400098527886E0F7030069857D2E4169EE7' });
    expect(result.success).toBe(false);
  });

  it('rejects dangerous signature', () => {
    const result = walletLoginSchema.safeParse({
      walletAddress: '0x52908400098527886E0F7030069857D2E4169EE7',
      signature: 'javascript:alert(1)',
      nonce: '123',
    });
    expect(result.success).toBe(false);
  });
});

describe('profileUpdateSchema', () => {
  it('accepts partial profile data', () => {
    const result = profileUpdateSchema.safeParse({ bio: 'Hello world' })
    expect(result.success).toBe(true)
  })

  it('rejects invalid avatar url', () => {
    const result = profileUpdateSchema.safeParse({ avatar: 'javascript:bad' })
    expect(result.success).toBe(false)
  })
})

describe('commentSchema', () => {
  it('rejects empty comment', () => {
    const result = commentSchema.safeParse({ content: '' })
    expect(result.success).toBe(false)
  })

  it('sanitizes script tags', () => {
    const result = commentSchema.safeParse({ content: '<script>alert(1)</script>Test' })
    expect(result.success).toBe(true)
    expect(result.data.content).toBe('Test')
  })
})

describe('searchSchema', () => {
  it('trims long queries', () => {
    const long = 'a'.repeat(150)
    const result = searchSchema.safeParse({ query: long })
    expect(result.success).toBe(false)
  })

  it('accepts normal query', () => {
    const result = searchSchema.safeParse({ query: 'bitcoin' })
    expect(result.success).toBe(true)
  })
})
