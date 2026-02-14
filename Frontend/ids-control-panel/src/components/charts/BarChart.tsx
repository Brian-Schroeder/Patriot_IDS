import {
  BarChart as RechartsBar,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import type { TrafficStats, SeverityDistribution, AttackTypeStats } from '../../types';

type BarChartData = TrafficStats | SeverityDistribution | AttackTypeStats;

interface BarChartProps {
  data: BarChartData[];
  dataKey: string;
  valueKey: string;
  title?: string;
}

export function BarChart({ data, dataKey, valueKey, title }: BarChartProps) {
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
            }}
            labelStyle={{ color: 'var(--ids-text)' }}
          />
          <Bar dataKey={valueKey} fill="var(--ids-accent)" radius={[4, 4, 0, 0]} />
        </RechartsBar>
      </ResponsiveContainer>
    </div>
  );
}
