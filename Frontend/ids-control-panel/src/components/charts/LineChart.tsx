import {
  LineChart as RechartsLine,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import type { TrafficStats } from '../../types';

interface LineChartProps {
  data: TrafficStats[];
  title?: string;
}

export function LineChartComponent({ data, title }: LineChartProps) {
  return (
    <div className="w-full h-full min-h-[300px]">
      {title && (
        <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height="100%" minHeight={300}>
        <RechartsLine data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--ids-border)" opacity={0.5} />
          <XAxis
            dataKey="hour"
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
          <Legend />
          <Line
            type="monotone"
            dataKey="totalPackets"
            stroke="var(--ids-accent)"
            strokeWidth={2}
            name="Total Packets"
            dot={{ fill: 'var(--ids-accent)' }}
          />
          <Line
            type="monotone"
            dataKey="alerts"
            stroke="var(--ids-danger)"
            strokeWidth={2}
            name="Alerts"
            dot={{ fill: 'var(--ids-danger)' }}
          />
        </RechartsLine>
      </ResponsiveContainer>
    </div>
  );
}
