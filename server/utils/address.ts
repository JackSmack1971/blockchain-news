import { ethers } from 'ethers';

export interface AddressValidation {
  valid: boolean;
  address?: string;
  error?: string;
}

/**
 * Validate and normalize an Ethereum address.
 */
export function validateEthereumAddress(address: unknown): AddressValidation {
  if (typeof address !== 'string') {
    return { valid: false, error: 'Address must be a string' };
  }
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return { valid: false, error: 'Invalid Ethereum address format' };
  }
  try {
    return { valid: true, address: ethers.getAddress(address) };
  } catch {
    return { valid: false, error: 'Invalid address checksum' };
  }
}
