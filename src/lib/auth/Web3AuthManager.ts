import { ethers } from 'ethers';
import { isValidEthereumAddress } from '../validators';

/**
 * Web3 authentication helper for wallet connection and message signing.
 */
export class Web3AuthManager {
  constructor(private providerFactory: () => ethers.BrowserProvider = () => new ethers.BrowserProvider((window as any).ethereum)) {}

  async connectWallet(): Promise<{ address: string; signer: ethers.Signer }> {
    if (!(window as any).ethereum) {
      throw new Error('Web3 wallet not detected');
    }
    try {
      const provider = this.providerFactory();
      await provider.send('eth_requestAccounts', []);
      const signer = await provider.getSigner();
      const address = await signer.getAddress();
      if (!isValidEthereumAddress(address)) {
        throw new Error('Invalid wallet address format');
      }
      return { address, signer };
    } catch (error: any) {
      throw new Error(`Wallet connection failed: ${error.message}`);
    }
  }

  async signAuthMessage(nonce: string, address: string): Promise<string> {
    if (!(window as any).ethereum) {
      throw new Error('Web3 wallet not available');
    }
    const provider = this.providerFactory();
    const signer = await provider.getSigner();
    const message = `BlockchainNews Authentication\nNonce: ${nonce}\nAddress: ${address}\nTimestamp: ${Date.now()}`;
    try {
      const signature = await signer.signMessage(message);
      if (!/^0x[a-fA-F0-9]{130}$/.test(signature)) {
        throw new Error('Invalid signature format');
      }
      return signature;
    } catch (error: any) {
      throw new Error(`Message signing failed: ${error.message}`);
    }
  }
}

export default Web3AuthManager;
