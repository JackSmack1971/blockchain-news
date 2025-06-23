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
