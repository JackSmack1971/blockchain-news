import { useCallback, useDeferredValue, useEffect, useState } from 'react';
import CacheManager from '../lib/data/CacheManager';
import { logError } from '../lib/errors';

export interface ChartPoint { time: number; value: number; }
interface ChartState { data: ChartPoint[]; loading: boolean; error: string | null; }

const cache = new CacheManager({ ttl: 60 });

export default function useChartData(
  key: string,
  fetcher: () => Promise<ChartPoint[]>,
  maxPoints = 1000,
) {
  const [state, setState] = useState<ChartState>({ data: [], loading: true, error: null });
  const deferredData = useDeferredValue(state.data);

  const load = useCallback(async () => {
    setState(s => ({ ...s, loading: true, error: null }));
    try {
      const cached = await cache.get<ChartPoint[]>(key);
      const points = cached ?? await fetcher();
      if (!cached) await cache.set(key, points);
      setState({ data: points.slice(-maxPoints), loading: false, error: null });
    } catch (err) {
      setState({ data: [], loading: false, error: (err as Error).message });
      logError(err, 'useChartData');
    }
  }, [key, fetcher, maxPoints]);

  const addPoint = useCallback((p: ChartPoint) => {
    setState(s => ({ ...s, data: [...s.data, p].slice(-maxPoints) }));
  }, [maxPoints]);

  useEffect(() => { load(); }, [load]);

  return { data: deferredData, loading: state.loading, error: state.error, addPoint };
}
