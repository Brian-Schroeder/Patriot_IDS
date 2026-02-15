import { create } from 'zustand';
import type { ChartType } from '../types';

export type TimeRange = '1m' | '5m' | '15m' | '30m' | '1h' | '24h';

interface ChartStore {
  chartType: ChartType;
  timeRange: TimeRange;
  setChartType: (type: ChartType) => void;
  setTimeRange: (range: TimeRange) => void;
}

export const useChartStore = create<ChartStore>((set) => ({
  chartType: 'bar',
  timeRange: '5m',
  setChartType: (chartType) => set({ chartType }),
  setTimeRange: (timeRange) => set({ timeRange }),
}));
