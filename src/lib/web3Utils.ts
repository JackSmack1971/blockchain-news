import { isValidEthereumAddress } from './validators';

/**
 * Generate an EIP-4361 sign-in message.
 * @param address Wallet address in checksum format
 * @param nonce Unique nonce provided by the backend
 * @returns Formatted message string
 */
export function generateSignInMessage(address: string, nonce: string): string {
  if (!isValidEthereumAddress(address)) {
    throw new Error('Invalid Ethereum address');
  }
  if (!nonce || typeof nonce !== 'string') {
    throw new Error('Invalid nonce');
  }

  const domain = window.location.host;
  const origin = window.location.origin;
  const timestamp = new Date().toISOString();

  return `${domain} wants you to sign in with your Ethereum account:\n${address}\n\nSign in to BlockchainNews\n\nURI: ${origin}\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: ${timestamp}`;
}
