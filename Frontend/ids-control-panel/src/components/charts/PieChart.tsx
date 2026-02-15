import { PieChart as RechartsPie, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import type { SeverityDistribution } from '../../types';

interface PieChartProps {
  data: SeverityDistribution[];
  title?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  low: '#22c55e',
  medium: '#fbbf24',
  high: '#f97316',
  critical: '#ef4444',
};

export function PieChartComponent({ data, title }: PieChartProps) {
  const chartData = (data ?? []).filter((d) => (d.count ?? 0) > 0);
  if (!chartData.length) {
    return (
      <div className="w-full min-h-[400px] flex flex-col items-center justify-center text-[var(--ids-text-muted)]">
        {title && <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>}
        <p>No severity data to display</p>
      </div>
    );
  }
  return (
    <div className="w-full h-full min-h-[450px]">
      {title && (
        <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height={400}>
        <RechartsPie>
          <Pie
            data={chartData}
            dataKey="count"
            nameKey="severity"
            cx="50%"
            cy="50%"
            outerRadius={100}
            label={({ name, value }) => `${name}: ${value}`}
          >
            {chartData.map((entry, index) => (
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
