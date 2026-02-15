import { BarChart3, LineChart, Circle, PieChart, Clock } from 'lucide-react';
import type { ChartType } from '../types';
import { useChartStore } from '../store/chartStore';

const chartOptions: { type: ChartType; label: string; icon: React.ReactNode }[] = [
  { type: 'bar', label: 'Bar Chart', icon: <BarChart3 size={18} /> },
  { type: 'line', label: 'Line Chart', icon: <LineChart size={18} /> },
  { type: 'dotplot', label: 'Dot Plot', icon: <Circle size={18} /> },
  { type: 'pie', label: 'Pie Chart', icon: <PieChart size={18} /> },
];

import type { TimeRange } from '../store/chartStore';

const timeOptions: { range: TimeRange; label: string }[] = [
  { range: '1m', label: '1 Min' },
  { range: '5m', label: '5 Min' },
  { range: '15m', label: '15 Min' },
  { range: '30m', label: '30 Min' },
  { range: '1h', label: '1 Hour' },
  { range: '24h', label: '24 Hours' },
];

export function ChartSelector() {
  const { chartType, timeRange, setChartType, setTimeRange } = useChartStore();

  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="flex items-center gap-2">
        <span className="text-sm text-[var(--ids-text-muted)]">Chart Type:</span>
        <div className="flex gap-1">
          {chartOptions.map(({ type, label, icon }) => (
            <button
              key={type}
              onClick={() => setChartType(type)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                chartType === type
                  ? 'bg-[var(--ids-accent)] text-[var(--ids-bg)] shadow-sm'
                  : 'bg-[var(--ids-border)]/30 text-[var(--ids-text-muted)] hover:bg-[var(--ids-border)]/60 hover:text-[var(--ids-text)]'
              }`}
            >
              {icon}
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Clock size={16} className="text-[var(--ids-text-muted)]" />
        <span className="text-sm text-[var(--ids-text-muted)]">Time Range:</span>
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value as typeof timeRange)}
          className="px-4 py-2 rounded-lg bg-[var(--ids-surface)] border border-[var(--ids-border)] text-[var(--ids-text)] font-medium text-sm focus:outline-none focus:ring-2 focus:ring-[var(--ids-accent)] focus:border-transparent cursor-pointer"
        >
          {timeOptions.map(({ range, label }) => (
            <option key={range} value={range}>
              {label}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
