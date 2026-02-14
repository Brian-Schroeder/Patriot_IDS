import { PieChart as RechartsPie, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import type { SeverityDistribution } from '../../types';

interface PieChartProps {
  data: SeverityDistribution[];
  title?: string;
}

const COLORS = [
  'var(--ids-accent)',
  'var(--ids-warn)',
  '#f97316',
  'var(--ids-danger)',
];

export function PieChartComponent({ data, title }: PieChartProps) {
  return (
    <div className="w-full h-full min-h-[300px]">
      {title && (
        <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height="100%" minHeight={300}>
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
            {data.map((_, index) => (
              <Cell key={index} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: 'var(--ids-surface)',
              border: '1px solid var(--ids-border)',
              borderRadius: '8px',
            }}
          />
          <Legend />
        </RechartsPie>
      </ResponsiveContainer>
    </div>
  );
}
