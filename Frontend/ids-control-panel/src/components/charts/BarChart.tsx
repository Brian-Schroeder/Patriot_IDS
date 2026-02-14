import {
  BarChart as RechartsBar,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  Rectangle,
} from 'recharts';
import type { TrafficStats, SeverityDistribution, AttackTypeStats } from '../../types';

type BarChartData = TrafficStats | SeverityDistribution | AttackTypeStats;

const SEVERITY_COLORS: Record<string, string> = {
  low: '#22c55e',
  medium: '#fbbf24',
  high: '#f97316',
  critical: '#ef4444',
};

/** Blend severity colors by percentage. Returns hex color. */
function mixSeverityColors(severityCounts: Record<string, number>, total: number): string {
  if (total === 0) return '#00d4aa';
  const hexToRgb = (hex: string) => {
    const m = hex.match(/^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i);
    return m ? [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)] : [0, 0, 0];
  };
  const rgbToHex = (r: number, g: number, b: number) =>
    '#' + [r, g, b].map((x) => Math.round(Math.min(255, Math.max(0, x))).toString(16).padStart(2, '0')).join('');
  let r = 0, g = 0, b = 0;
  for (const [sev, count] of Object.entries(severityCounts)) {
    if (count <= 0) continue;
    const p = count / total;
    const [sr, sg, sb] = hexToRgb(SEVERITY_COLORS[sev] ?? '#00d4aa');
    r += sr * p;
    g += sg * p;
    b += sb * p;
  }
  return rgbToHex(r, g, b);
}

interface BarChartProps {
  data: BarChartData[];
  dataKey: string;
  valueKey: string;
  title?: string;
  variant?: 'default' | 'severity' | 'alertsByHour';
  xAxisLabel?: string;
  yAxisLabel?: string;
}

export function BarChart({
  data,
  dataKey,
  valueKey,
  title,
  variant = 'default',
  xAxisLabel,
  yAxisLabel,
}: BarChartProps) {
  const getBarFill = (entry: BarChartData): string => {
    if (variant === 'alertsByHour') {
      const t = entry as TrafficStats;
      const counts = t.severityCounts ?? {};
      const total = t.alerts ?? 0;
      return mixSeverityColors(counts, total);
    }
    if (variant === 'severity') {
      const val = (entry as unknown as Record<string, unknown>)[dataKey];
      return (val ? SEVERITY_COLORS[String(val)] : null) ?? '#00d4aa';
    }
    return '#00d4aa';
  };

  const expandAmount = 4;
  const ExpandedBar = (props: { width?: number; x?: number; fill?: string; [k: string]: unknown }) => (
    <Rectangle
      {...props}
      fill={props.fill ?? '#00d4aa'}
      width={(props.width ?? 0) + expandAmount * 2}
      x={(props.x ?? 0) - expandAmount}
    />
  );

  return (
    <div className="w-full h-full min-h-[400px]">
      {title && (
        <h3 className="text-lg font-semibold mb-4 text-[var(--ids-text)]">{title}</h3>
      )}
      <ResponsiveContainer width="100%" height="100%" minHeight={400}>
        <RechartsBar data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--ids-border)" opacity={0.5} />
          <XAxis
            dataKey={dataKey}
            stroke="var(--ids-text-muted)"
            tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
            label={xAxisLabel ? { value: xAxisLabel, position: 'insideBottom', offset: -5, fill: 'var(--ids-text-muted)', fontSize: 12 } : undefined}
          />
          <YAxis
            stroke="var(--ids-text-muted)"
            tick={{ fill: 'var(--ids-text-muted)', fontSize: 12 }}
            label={yAxisLabel ? { value: yAxisLabel, angle: -90, position: 'insideLeft', fill: 'var(--ids-text-muted)', fontSize: 12 } : undefined}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'var(--ids-surface)',
              border: '1px solid var(--ids-border)',
              borderRadius: '8px',
              color: '#ffffff',
            }}
            labelStyle={{ color: '#ffffff' }}
            itemStyle={{ color: '#ffffff' }}
            content={({ active, payload, label }) =>
              active && payload?.[0] ? (
                <div
                  className="px-3 py-2 rounded-lg border border-[var(--ids-border)]"
                  style={{
                    backgroundColor: 'var(--ids-surface)',
                    color: '#ffffff',
                  }}
                >
                  <div className="font-medium">{label}</div>
                  <div style={{ color: '#ffffff' }}>
                    {valueKey === 'alerts' ? 'Alerts' : 'Count'}: {payload[0].value}
                  </div>
                </div>
              ) : null
            }
          />
          <Bar
            dataKey={valueKey}
            fill="#00d4aa"
            radius={[4, 4, 0, 0]}
            activeBar={(props) => <ExpandedBar {...props} />}
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
