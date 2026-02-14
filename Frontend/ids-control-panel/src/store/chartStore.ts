import { create } from 'zustand';
import type { ChartType } from '../types';

interface ChartStore {
  chartType: ChartType;
  timeRange: '1h' | '6h' | '24h' | '7d';
  setChartType: (type: ChartType) => void;
  setTimeRange: (range: '1h' | '6h' | '24h' | '7d') => void;
}

export const useChartStore = create<ChartStore>((set) => ({
  chartType: 'bar',
  timeRange: '24h',
  setChartType: (chartType) => set({ chartType }),
  setTimeRange: (timeRange) => set({ timeRange }),
}));
