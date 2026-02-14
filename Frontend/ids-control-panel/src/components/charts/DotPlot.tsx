import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ZAxis,
} from 'recharts';
import type { IntrusionAlert } from '../../types';

interface DotPlotProps {
  data: IntrusionAlert[];
  title?: string;
}

const severityOrder = { low: 1, medium: 2, high: 3, critical: 4 };

export function DotPlot({ data, title }: DotPlotProps) {
  const scatterData = data.slice(0, 100).map((a) => ({
    x: new Date(a.timestamp).getTime(),
    y: a.packetCount,
    z: severityOrder[a.severity],
    attackType: a.attackType,
    severity: a.severity,
    sourceIp: a.sourceIp,
  }));

  return (
    <div className="w-full h-full min-h-[300px]">
      {title && (
        <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height="100%" minHeight={300}>
        <ScatterChart margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--ids-border)" opacity={0.5} />
          <XAxis
            type="number"
            dataKey="x"
            name="Time"
            stroke="var(--ids-text-muted)"
            tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
            tickFormatter={(ts) => new Date(ts).toLocaleTimeString()}
          />
          <YAxis
            type="number"
            dataKey="y"
            name="Packets"
            stroke="var(--ids-text-muted)"
            tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
          />
          <ZAxis type="number" dataKey="z" range={[100, 400]} name="Severity" />
          <Tooltip
            cursor={{ strokeDasharray: '3 3', stroke: 'var(--ids-border)' }}
            contentStyle={{
              backgroundColor: 'var(--ids-surface)',
              border: '1px solid var(--ids-border)',
              borderRadius: '8px',
            }}
            content={({ active, payload }) =>
              active && payload?.[0] ? (
                <div className="text-sm p-2">
                  <div>Time: {new Date(payload[0].payload.x).toLocaleString()}</div>
                  <div>Packets: {payload[0].payload.y}</div>
                  <div>Type: {payload[0].payload.attackType}</div>
                  <div>Severity: {payload[0].payload.severity}</div>
                  <div>Source: {payload[0].payload.sourceIp}</div>
                </div>
              ) : null
            }
          />
          <Scatter
            name="Alerts"
            data={scatterData}
            fill="var(--ids-accent)"
            fillOpacity={0.7}
          />
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
}
