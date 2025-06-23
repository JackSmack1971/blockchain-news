import { z } from 'zod';
import { getAddress } from 'ethers';
import { sanitizeInput } from './security';
import { loginSchema, registerSchema } from './validation';


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



export const ethereumAddressSchema = z
  .string()
  .transform(val => sanitizeInput(val))
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
  signature: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().min(1)),
  nonce: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().min(1))
    .optional(),
});
