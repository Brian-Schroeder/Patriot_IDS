import { BarChart3, LineChart, Circle, Box, PieChart, Clock } from 'lucide-react';
import type { ChartType } from '../types';
import { useChartStore } from '../store/chartStore';

const chartOptions: { type: ChartType; label: string; icon: React.ReactNode }[] = [
  { type: 'bar', label: 'Bar Chart', icon: <BarChart3 size={18} /> },
  { type: 'line', label: 'Line Chart', icon: <LineChart size={18} /> },
  { type: 'dotplot', label: 'Dot Plot', icon: <Circle size={18} /> },
  { type: 'boxplot', label: 'Box Plot', icon: <Box size={18} /> },
  { type: 'pie', label: 'Pie Chart', icon: <PieChart size={18} /> },
];

const timeOptions: { range: '1h' | '6h' | '24h' | '7d'; label: string }[] = [
  { range: '1h', label: '1 Hour' },
  { range: '6h', label: '6 Hours' },
  { range: '24h', label: '24 Hours' },
  { range: '7d', label: '7 Days' },
];

export function ChartSelector() {
  const { chartType, timeRange, setChartType, setTimeRange } = useChartStore();

  return (
    <div className="flex flex-wrap items-center gap-4 p-4 rounded-lg bg-[var(--ids-surface)] border border-[var(--ids-border)]">
      <div className="flex items-center gap-2">
        <span className="text-sm text-[var(--ids-text-muted)]">Chart Type:</span>
        <div className="flex gap-1">
          {chartOptions.map(({ type, label, icon }) => (
            <button
              key={type}
              onClick={() => setChartType(type)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                chartType === type
                  ? 'bg-[var(--ids-accent)] text-[var(--ids-bg)]'
                  : 'bg-[var(--ids-border)]/50 text-[var(--ids-text-muted)] hover:bg-[var(--ids-border)] hover:text-[var(--ids-text)]'
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
          className="px-3 py-1.5 rounded bg-[var(--ids-border)] border border-[var(--ids-border)] text-[var(--ids-text)] font-medium text-sm focus:outline-none focus:ring-2 focus:ring-[var(--ids-accent)]"
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
