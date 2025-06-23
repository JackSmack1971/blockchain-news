import { z } from 'zod';
import { getAddress } from 'ethers';

export const isValidEthereumAddress = (address: string): boolean => {
  if (!address || typeof address !== 'string') return false;
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return false;
  try {
    const checksumAddress = getAddress(address);
    return address === checksumAddress;
  } catch {
    return false;
  }
};

const PASSWORD_REGEX = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,20}$/;

export const loginSchema = z.object({
  email: z.string().email(),
  password: z
    .string()
    .min(8)
    .regex(
      PASSWORD_REGEX,
      'Password must contain letters, numbers and symbols',
    ),
});

export const registerSchema = z
  .object({
    username: z
      .string()
      .min(3)
      .max(20)
      .regex(
        USERNAME_REGEX,
        'Username can only contain letters, numbers, underscores and hyphens',
      ),
    email: z.string().email(),
    password: z
      .string()
      .min(8)
      .regex(
        PASSWORD_REGEX,
        'Password must contain letters, numbers and symbols',
      ),
    confirmPassword: z
      .string()
      .min(8)
      .regex(
        PASSWORD_REGEX,
        'Password must contain letters, numbers and symbols',
      ),
  })
  .refine(data => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

export const ethereumAddressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address format')
  .refine(address => {
    try {
      getAddress(address);
      return true;
    } catch {
      return false;
    }
  }, 'Invalid address checksum');

export const walletLoginSchema = z.object({
  walletAddress: ethereumAddressSchema,
  signature: z.string().min(1),
  nonce: z.string().min(1).optional(),
});

export interface ValidationRule {
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  sanitize?: (value: string) => string;
}

export interface ValidationResult {
  isValid: boolean;
  error?: string;
  value?: string;
}

export const validationRules = {
  username: {
    required: true,
    minLength: 3,
    maxLength: 30,
    pattern: /^[a-zA-Z0-9_-]+$/,
    sanitize: (value: string) => value.trim().toLowerCase(),
  },
  email: {
    required: true,
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    maxLength: 254,
    sanitize: (value: string) => value.trim().toLowerCase(),
  },
  password: {
    required: true,
    minLength: 8,
    maxLength: 128,
    pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
  },
} as const;

export function validateInput(value: string, rules: ValidationRule): ValidationResult {
  const sanitized = rules.sanitize ? rules.sanitize(value) : value;

  const dangerousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=\s*/gi,
    /data:text\/html/gi,
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(sanitized)) {
      return { isValid: false, error: 'Invalid characters detected' };
    }
  }

  if (rules.required && !sanitized) {
    return { isValid: false, error: 'This field is required' };
  }

  if (rules.minLength && sanitized.length < rules.minLength) {
    return { isValid: false, error: `Minimum length is ${rules.minLength}` };
  }

  if (rules.maxLength && sanitized.length > rules.maxLength) {
    return { isValid: false, error: `Maximum length is ${rules.maxLength}` };
  }

  if (rules.pattern && !rules.pattern.test(sanitized)) {
    return { isValid: false, error: 'Invalid format' };
  }

  return { isValid: true, value: sanitized };
}
