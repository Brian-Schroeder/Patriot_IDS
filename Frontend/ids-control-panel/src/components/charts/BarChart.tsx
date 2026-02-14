import {
  BarChart as RechartsBar,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import type { TrafficStats, SeverityDistribution, AttackTypeStats } from '../../types';

type BarChartData = TrafficStats | SeverityDistribution | AttackTypeStats;

const SEVERITY_COLORS: Record<string, string> = {
  low: 'var(--ids-severity-low)',
  medium: 'var(--ids-severity-medium)',
  high: 'var(--ids-severity-high)',
  critical: 'var(--ids-severity-critical)',
};

interface BarChartProps {
  data: BarChartData[];
  dataKey: string;
  valueKey: string;
  title?: string;
  variant?: 'default' | 'severity';
}

export function BarChart({ data, dataKey, valueKey, title, variant = 'default' }: BarChartProps) {
  const getBarFill = (entry: BarChartData): string => {
    if (variant !== 'severity') return 'var(--ids-accent)';
    const val = (entry as unknown as Record<string, unknown>)[dataKey];
    return (val ? SEVERITY_COLORS[String(val)] : null) ?? 'var(--ids-accent)';
  };

  return (
    <div className="w-full h-full min-h-[300px]">
      {title && (
        <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height="100%" minHeight={300}>
        <RechartsBar data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--ids-border)" opacity={0.5} />
          <XAxis
            dataKey={dataKey}
            stroke="var(--ids-text-muted)"
            tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
          />
          <YAxis
            stroke="var(--ids-text-muted)"
            tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'var(--ids-surface)',
              border: '1px solid var(--ids-border)',
              borderRadius: '8px',
              color: 'var(--ids-text)',
            }}
            labelStyle={{ color: 'var(--ids-text)' }}
          />
          <Bar
            dataKey={valueKey}
            radius={[4, 4, 0, 0]}
            activeBar={{ fill: 'rgba(0, 212, 170, 0.4)', stroke: 'var(--ids-accent)', strokeWidth: 1 }}
          >
            {data.map((entry, index) => (
              <Cell key={index} fill={getBarFill(entry)} />
            ))}
          </Bar>
        </RechartsBar>
      </ResponsiveContainer>
    </div>
  );
}
