import { describe, it, expect, beforeEach } from 'vitest';
import { Wallet } from 'ethers';
import { parseEip4361Message, verifyEip4361Signature, _test } from '../utils/web3Auth';

process.env.SIGNIN_DOMAIN = 'localhost:3001';
process.env.SIGNIN_CHAIN_ID = '1';

const buildMessage = (address: string, nonce: string) => {
  return `${process.env.SIGNIN_DOMAIN} wants you to sign in with your Ethereum account:\n${address}\n\nSign in to BlockchainNews\n\nURI: http://${process.env.SIGNIN_DOMAIN}\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}`;
};

beforeEach(() => {
  _test.memSigs.clear();
});

describe('web3Auth utilities', () => {
  it('parses valid EIP-4361 message', () => {
    const msg = buildMessage('0x000000000000000000000000000000000000dEaD', 'n');
    const parsed = parseEip4361Message(msg);
    expect(parsed.address).toBe('0x000000000000000000000000000000000000dEaD');
  });

  it('rejects invalid signature', async () => {
    const wallet = Wallet.createRandom();
    const msg = buildMessage(wallet.address, 'a');
    const sig = await wallet.signMessage('bad');
    await expect(verifyEip4361Signature(msg, sig)).rejects.toThrow();
  });

  it('prevents signature reuse', async () => {
    const wallet = Wallet.createRandom();
    const msg = buildMessage(wallet.address, 'a');
    const sig = await wallet.signMessage(msg);
    await verifyEip4361Signature(msg, sig);
    await expect(verifyEip4361Signature(msg, sig)).rejects.toThrow();
  });
});
