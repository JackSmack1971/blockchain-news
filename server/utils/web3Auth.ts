import { ethers } from 'ethers';
import Redis from 'ioredis';
import { logSecurityEvent } from '../logging';

export class Web3AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Web3AuthError';
  }
}

export interface Eip4361Message {
  domain: string;
  address: string;
  statement: string;
  uri: string;
  version: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
}

let redis: Redis | null = null;
function getRedis(): Redis | null {
  if (!redis && process.env.REDIS_URL) {
    redis = new Redis(process.env.REDIS_URL, { lazyConnect: true });
  }
  return redis;
}

const memSigs = new Map<string, number>();

export function parseEip4361Message(message: string): Eip4361Message {
  try {
    const l = message.split('\n');
    const m = l[0]?.match(/^(.*) wants you to sign in with your Ethereum account:?$/);
    const addr = l[1];
    if (!m || !/^0x[a-fA-F0-9]{40}$/.test(addr)) throw new Web3AuthError('Invalid message format');
    const g = (p: string) => l.find(v => v.startsWith(p))?.slice(p.length).trim() || '';
    const res = {
      domain: m[1],
      address: ethers.getAddress(addr),
      statement: l[3] || '',
      uri: g('URI: '),
      version: g('Version: '),
      chainId: Number(g('Chain ID: ')),
      nonce: g('Nonce: '),
      issuedAt: g('Issued At: '),
    } as Eip4361Message;
    if (
      res.domain !== process.env.SIGNIN_DOMAIN ||
      res.chainId !== Number(process.env.SIGNIN_CHAIN_ID) ||
      !res.uri || !res.version || !res.nonce || !res.issuedAt
    ) throw new Web3AuthError('Invalid message format');
    const ts = Date.parse(res.issuedAt);
    if (Number.isNaN(ts) || Math.abs(Date.now() - ts) > 300000) throw new Web3AuthError('Message expired');
    return res;
  } catch (err) {
    if (err instanceof Web3AuthError) throw err;
    throw new Web3AuthError('Invalid message format');
  }
}

async function markSignatureUsed(sig: string, ttl = 300): Promise<void> {
  memSigs.set(sig, Date.now() + ttl * 1000);
  const client = getRedis();
  if (!client) return;
  try {
    await client.set(`sig:${sig}`, '1', 'EX', ttl);
  } catch (err) {
    await logSecurityEvent('redis_error', { msg: 'set_signature', error: (err as Error).message });
  }
}

async function isSignatureUsed(sig: string): Promise<boolean> {
  const exp = memSigs.get(sig);
  if (exp && exp > Date.now()) return true;
  if (exp) memSigs.delete(sig);
  const client = getRedis();
  if (!client) return false;
  try {
    const res = await client.exists(`sig:${sig}`);
    return res === 1;
  } catch (err) {
    await logSecurityEvent('redis_error', { msg: 'check_signature', error: (err as Error).message });
    return false;
  }
}

export async function verifyEip4361Signature(message: string, signature: string): Promise<Eip4361Message> {
  const parsed = parseEip4361Message(message);
  try {
    const recovered = ethers.verifyMessage(message, signature);
    if (recovered.toLowerCase() !== parsed.address.toLowerCase()) {
      throw new Web3AuthError('Invalid signature');
    }
    if (await isSignatureUsed(signature)) throw new Web3AuthError('Signature already used');
    await markSignatureUsed(signature);
    return parsed;
  } catch (err) {
    if (err instanceof Web3AuthError) throw err;
    throw new Web3AuthError('Invalid signature');
  }
}

export const _test = { isSignatureUsed, memSigs, markSignatureUsed };
