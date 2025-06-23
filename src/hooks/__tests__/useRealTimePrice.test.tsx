import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { EventEmitter } from 'events';

class FakeStream extends EventEmitter {
  static instances: FakeStream[] = [];
  connect = vi.fn();
  cleanup = vi.fn();
  constructor() {
    super();
    FakeStream.instances.push(this);
  }
}
vi.mock('../lib/data/CryptoDataStream', () => ({
  default: FakeStream,
  CryptoStreamError: class extends Error {},
}));


describe('useRealTimePrice', () => {
  beforeEach(() => {
    FakeStream.instances.length = 0;
    vi.useFakeTimers();
  });

  it('throttles price updates', async () => {
    const { default: useRealTimePrice } = await import('../useRealTimePrice');
    const { result } = renderHook(() => useRealTimePrice('BTCUSDT'));
    const stream = FakeStream.instances[0];
    act(() => {
      stream.emit('message', { data: { c: 1 } });
      stream.emit('message', { data: { c: 2 } });
    });
    expect(result.current.price).toBe(1);
    vi.advanceTimersByTime(201);
    act(() => stream.emit('message', { data: { c: 3 } }));
    expect(result.current.price).toBe(3);
  });

  it('cleans up on unmount', async () => {
    const { default: useRealTimePrice } = await import('../useRealTimePrice');
    const { unmount } = renderHook(() => useRealTimePrice('ETHUSDT'));
    const stream = FakeStream.instances[0];
    unmount();
    expect(stream.cleanup).toHaveBeenCalled();
  });
});
