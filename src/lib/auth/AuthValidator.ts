import { isValidEthereumAddress } from '../validators';
import { sanitizeHtml } from '../sanitizeHtml';

export const sanitizeNonce = (nonce: string): string => {
  return nonce.replace(/[^a-zA-Z0-9]/g, '').slice(0, 64);
};

export const sanitizeAddress = (address: string): string => {
  const trimmed = address.trim();
  return isValidEthereumAddress(trimmed) ? trimmed : '';
};

export const sanitizeMessage = (message: string): string => {
  return sanitizeHtml(message).slice(0, 2000);
};
