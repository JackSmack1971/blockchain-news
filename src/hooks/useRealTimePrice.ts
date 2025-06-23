import { useCallback, useEffect, useRef, useState } from 'react';
import { unstable_batchedUpdates } from 'react-dom';
import CryptoDataStream, { CryptoStreamError, DataEvent } from '../lib/data/CryptoDataStream';
import { logError } from '../lib/errors';

interface PriceState { price: number | null; loading: boolean; error: string | null; }

const THROTTLE_MS = 200;

export default function useRealTimePrice(symbol: string): PriceState {
  const [state, setState] = useState<PriceState>({ price: null, loading: true, error: null });
  const lastRef = useRef(0);

  const handleMessage = useCallback(({ data }: DataEvent) => {
    const now = Date.now();
    const price = Number((data as any).c ?? (data as any).price);
    if (Number.isNaN(price) || now - lastRef.current < THROTTLE_MS) return;
    lastRef.current = now;
    unstable_batchedUpdates(() => setState(p => ({ ...p, price, loading: false })));
  }, []);

  const handleError = useCallback((err: CryptoStreamError) => {
    unstable_batchedUpdates(() => setState({ price: null, loading: false, error: err.message }));
    logError(err, 'useRealTimePrice');
  }, []);

  useEffect(() => {
    if (!/^[A-Za-z0-9]{2,20}$/.test(symbol)) {
      setState({ price: null, loading: false, error: 'Invalid symbol' });
      return;
    }
    const stream = new CryptoDataStream();
    stream.on('message', handleMessage);
    stream.on('error', handleError);
    try { stream.connect([symbol]); } catch (err) { handleError(err as CryptoStreamError); }
    return () => { stream.cleanup(); stream.off('message', handleMessage); stream.off('error', handleError); };
  }, [symbol, handleMessage, handleError]);

  return state;
}
