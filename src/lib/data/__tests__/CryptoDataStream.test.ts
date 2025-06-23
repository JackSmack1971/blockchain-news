import { describe, it, expect, vi, beforeEach } from 'vitest';

let CryptoDataStream: any;
let CryptoStreamError: any;

declare global {
  interface Window { WebSocket: any }
}

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  onopen?: () => void;
  onmessage?: (ev: { data: string }) => void;
  onclose?: () => void;
  onerror?: () => void;
  constructor(public url: string) {
    MockWebSocket.instances.push(this);
  }
  close() {
    if (this.onclose) this.onclose();
  }
  emitMessage(data: unknown) {
    if (this.onmessage) this.onmessage({ data: JSON.stringify(data) });
  }
  triggerError() {
    if (this.onerror) this.onerror();
  }
  open() {
    if (this.onopen) this.onopen();
  }
}

vi.stubGlobal('WebSocket', MockWebSocket);

beforeEach(async () => {
  process.env.VITE_WS_BASE_URL = 'wss://example.com/ws';
  const mod = await import('../CryptoDataStream');
  CryptoDataStream = mod.default;
  CryptoStreamError = mod.CryptoStreamError;
  MockWebSocket.instances.length = 0;
  vi.clearAllTimers();
  vi.useFakeTimers();
});

describe('CryptoDataStream', () => {
  it('reconnects with backoff', () => {
    const stream = new CryptoDataStream();
    stream.connect(['BTCUSDT']);
    expect(MockWebSocket.instances.length).toBe(1);
    MockWebSocket.instances[0].close();
    vi.advanceTimersByTime(1000);
    expect(MockWebSocket.instances.length).toBe(2);
  });

  it('emits error after max retries', () => {
    const errors: CryptoStreamError[] = [];
    const stream = new CryptoDataStream({ maxRetries: 2 });
    stream.on('error', e => errors.push(e));
    stream.connect(['ETHUSDT']);
    MockWebSocket.instances[0].close();
    vi.advanceTimersByTime(1000);
    MockWebSocket.instances[1].close();
    vi.advanceTimersByTime(2000);
    MockWebSocket.instances[2].close();
    vi.advanceTimersByTime(4000);
    expect(errors[0]).toBeInstanceOf(CryptoStreamError);
  });

  it('throws on invalid symbol', () => {
    const stream = new CryptoDataStream();
    expect(() => stream.connect(['??'])).toThrow(CryptoStreamError);
  });
});

