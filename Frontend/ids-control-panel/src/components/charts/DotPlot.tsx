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
import { format } from 'date-fns';

interface DotPlotProps {
  data: IntrusionAlert[];
  title?: string;
}

const severityOrder = { low: 1, medium: 2, high: 3, critical: 4 };

export function DotPlot({ data, title }: DotPlotProps) {
  const scatterData = data.map((a) => ({
    x: new Date(a.timestamp).getTime(),
    y: a.packetCount,
    z: severityOrder[a.severity],
    attackType: a.attackType,
    severity: a.severity,
    sourceIp: a.sourceIp,
  }));

  const xMin = scatterData.length > 0 ? Math.min(...scatterData.map((d) => d.x)) : 0;
  const xMax = scatterData.length > 0 ? Math.max(...scatterData.map((d) => d.x)) : 0;
  const xRange = xMax - xMin;
  const padding = xRange * 0.02 || 3600000;

  const formatTimeTick = (ts: number) => {
    const d = new Date(ts);
    return xRange > 86400000
      ? format(d, 'MMM d HH:mm')
      : format(d, 'HH:mm:ss');
  };

  return (
    <div className="w-full h-full min-h-[450px]">
      {title && (
        <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height="100%" minHeight={420}>
        <ScatterChart margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--ids-border)" opacity={0.5} />
          <XAxis
            type="number"
            dataKey="x"
            stroke="var(--ids-text-muted)"
            tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
            tickFormatter={formatTimeTick}
            domain={[xMin - padding, xMax + padding]}
            label={{ value: 'Time', position: 'insideBottom', offset: -5, fill: 'var(--ids-text-muted)', fontSize: 12 }}
          />
          <YAxis
            type="number"
            dataKey="y"
            stroke="var(--ids-text-muted)"
            tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
            label={{ value: 'Packets', angle: -90, position: 'insideLeft', fill: 'var(--ids-text-muted)', fontSize: 12 }}
          />
          <ZAxis type="number" dataKey="z" range={[100, 400]} name="Severity" />
          <Tooltip
            cursor={{ strokeDasharray: '3 3', stroke: 'var(--ids-border)' }}
            contentStyle={{
              backgroundColor: 'var(--ids-surface)',
              border: '1px solid var(--ids-border)',
              borderRadius: '8px',
              color: '#ffffff',
            }}
            content={({ active, payload }) =>
              active && payload?.[0] ? (
                <div
                  className="text-sm p-2"
                  style={{ color: '#ffffff' }}
                >
                  <div>Time: {format(new Date(payload[0].payload.x), 'MMM d, yyyy HH:mm:ss')}</div>
                  <div>Packets: {payload[0].payload.y.toLocaleString()}</div>
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
