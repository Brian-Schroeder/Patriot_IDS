import { PieChart as RechartsPie, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import type { SeverityDistribution } from '../../types';

interface PieChartProps {
  data: SeverityDistribution[];
  title?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  low: 'var(--ids-severity-low)',
  medium: 'var(--ids-severity-medium)',
  high: 'var(--ids-severity-high)',
  critical: 'var(--ids-severity-critical)',
};

export function PieChartComponent({ data, title }: PieChartProps) {
  return (
    <div className="w-full h-full min-h-[450px]">
      {title && (
        <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height="100%" minHeight={400}>
        <RechartsPie>
          <Pie
            data={data}
            dataKey="count"
            nameKey="severity"
            cx="50%"
            cy="50%"
            outerRadius={100}
            label={({ name, value }) => `${name}: ${value}`}
          >
            {data.map((entry, index) => (
              <Cell
                key={index}
                fill={SEVERITY_COLORS[entry.severity] ?? 'var(--ids-accent)'}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: 'var(--ids-surface)',
              border: '1px solid var(--ids-border)',
              borderRadius: '8px',
              color: 'var(--ids-text)',
            }}
            itemStyle={{ color: 'var(--ids-text)' }}
            labelStyle={{ color: 'var(--ids-text)' }}
            content={({ active, payload }) =>
              active && payload?.[0] ? (
                <div
                  className="px-3 py-2 rounded-lg border border-[var(--ids-border)]"
                  style={{
                    backgroundColor: 'var(--ids-surface)',
                    color: 'var(--ids-text)',
                  }}
                >
                  <div className="font-medium">
                    {payload[0].name}: {payload[0].value}
                  </div>
                  {payload[0].payload && (
                    <div className="text-sm text-[var(--ids-text-muted)] mt-0.5">
                      {payload[0].payload.severity} severity
                    </div>
                  )}
                </div>
              ) : null
            }
          />
          <Legend wrapperStyle={{ color: 'var(--ids-text)' }} />
        </RechartsPie>
      </ResponsiveContainer>
    </div>
  );
}
