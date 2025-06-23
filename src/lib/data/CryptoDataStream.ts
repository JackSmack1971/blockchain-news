import { EventEmitter } from 'events';

export class CryptoStreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoStreamError';
  }
}

export interface StreamOptions {
  maxRetries?: number;
}

const DEFAULT_MAX_RETRIES = 5;
const BASE_URL =
  (typeof import.meta !== 'undefined' && (import.meta as any).env?.VITE_WS_BASE_URL) ||
  process.env.VITE_WS_BASE_URL;

const isValidSymbol = (symbol: string): boolean => /^[A-Za-z0-9]{2,20}$/.test(symbol);

export interface DataEvent {
  symbol: string;
  data: unknown;
}

export type CryptoDataStreamEvents = {
  open: (symbol: string) => void;
  message: (payload: DataEvent) => void;
  close: (symbol: string) => void;
  error: (err: CryptoStreamError) => void;
  reconnecting: (symbol: string, attempt: number) => void;
};

export default class CryptoDataStream extends EventEmitter {
  private sockets = new Map<string, WebSocket>();
  private attempts = new Map<string, number>();
  private maxRetries: number;

  constructor(options: StreamOptions = {}) {
    super();
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    if (!BASE_URL) {
      throw new CryptoStreamError('Missing WebSocket base URL');
    }
  }

  connect(symbols: string[]): void {
    symbols.forEach(symbol => this.subscribe(symbol));
  }

  subscribe(symbol: string): void {
    if (!isValidSymbol(symbol)) {
      throw new CryptoStreamError(`Invalid symbol: ${symbol}`);
    }
    const url = `${BASE_URL}/${symbol.toLowerCase()}@ticker`;
    const ws = new WebSocket(url);

    ws.onopen = () => this.emit('open', symbol);
    ws.onmessage = evt => {
      try {
        const data = JSON.parse(evt.data as string);
        this.emit('message', { symbol, data });
      } catch (err) {
        this.emit('error', new CryptoStreamError('Invalid message format'));
      }
    };
    ws.onerror = () => this.emit('error', new CryptoStreamError('WebSocket error'));
    ws.onclose = () => this.handleClose(symbol);

    this.sockets.set(symbol, ws);
    this.attempts.set(symbol, 0);
  }

  private handleClose(symbol: string): void {
    const attempt = (this.attempts.get(symbol) ?? 0) + 1;
    if (attempt > this.maxRetries) {
      this.emit('error', new CryptoStreamError('Max retries reached'));
      this.sockets.delete(symbol);
      return;
    }
    this.emit('reconnecting', symbol, attempt);
    this.attempts.set(symbol, attempt);
    const delay = 2 ** (attempt - 1) * 1000;
    setTimeout(() => this.subscribe(symbol), delay);
  }

  cleanup(): void {
    this.sockets.forEach(ws => ws.close());
    this.sockets.clear();
    this.attempts.clear();
  }
}
