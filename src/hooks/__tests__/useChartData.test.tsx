import { describe, it, expect, vi } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';

const get = vi.fn();
const set = vi.fn();
class MockCache { constructor(){ } get = get; set = set; }

vi.mock('../lib/data/CacheManager', () => ({ default: MockCache }));

import useChartData, { ChartPoint } from '../useChartData';

describe('useChartData', () => {
  it('uses cache and maintains window', async () => {
    get.mockResolvedValueOnce(null);
    const points: ChartPoint[] = [
      { time: 1, value: 1 },
      { time: 2, value: 2 },
      { time: 3, value: 3 },
    ];
    const fetcher = vi.fn().mockResolvedValue(points);
    const { result } = renderHook(() => useChartData('k', fetcher, 3));
    await waitFor(() => !result.current.loading);
    expect(fetcher).toHaveBeenCalled();
    act(() => result.current.addPoint({ time: 4, value: 4 }));
    expect(result.current.data.length).toBe(3);
    expect(result.current.data[0].time).toBe(2);
    expect(set).toHaveBeenCalled();
  });
});
