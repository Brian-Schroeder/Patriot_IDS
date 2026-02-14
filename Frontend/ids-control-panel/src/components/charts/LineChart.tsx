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
    <div className="w-full h-full min-h-[520px] space-y-8">
      {title && (
        <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>
      )}
      <div>
        <h4 className="text-sm font-medium text-[var(--ids-text-muted)] mb-3">Total Packets Over Time</h4>
        <ResponsiveContainer width="100%" height={380} minHeight={380}>
          <RechartsLine data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--ids-border)" opacity={0.5} />
            <XAxis
              dataKey="hour"
              stroke="var(--ids-text-muted)"
              tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
              label={{ value: 'Time', position: 'insideBottom', offset: -5, fill: 'var(--ids-text-muted)', fontSize: 12 }}
            />
            <YAxis
              stroke="var(--ids-text-muted)"
              tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
              label={{ value: 'Packets', angle: -90, position: 'insideLeft', fill: 'var(--ids-text-muted)', fontSize: 12 }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: 'var(--ids-surface)',
                border: '1px solid var(--ids-border)',
                borderRadius: '8px',
                color: '#ffffff',
              }}
              labelStyle={{ color: '#ffffff' }}
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
          </RechartsLine>
        </ResponsiveContainer>
      </div>
      <div>
        <h4 className="text-sm font-medium text-[var(--ids-text-muted)] mb-3">Alerts Over Time</h4>
        <ResponsiveContainer width="100%" height={380} minHeight={380}>
          <RechartsLine data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--ids-border)" opacity={0.5} />
            <XAxis
              dataKey="hour"
              stroke="var(--ids-text-muted)"
              tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
              label={{ value: 'Time', position: 'insideBottom', offset: -5, fill: 'var(--ids-text-muted)', fontSize: 12 }}
            />
            <YAxis
              stroke="var(--ids-text-muted)"
              tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
              label={{ value: 'Alerts', angle: -90, position: 'insideLeft', fill: 'var(--ids-text-muted)', fontSize: 12 }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: 'var(--ids-surface)',
                border: '1px solid var(--ids-border)',
                borderRadius: '8px',
                color: '#ffffff',
              }}
              labelStyle={{ color: '#ffffff' }}
            />
            <Legend />
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
    </div>
  );
}
