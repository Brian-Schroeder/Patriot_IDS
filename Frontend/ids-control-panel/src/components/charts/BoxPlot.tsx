import Plot from 'react-plotly.js';
import type { AttackTypeStats } from '../../types';

interface BoxPlotProps {
  data: AttackTypeStats[];
  title?: string;
}

export function BoxPlot({ data, title }: BoxPlotProps) {
  const boxData = data.map((d) => ({
    y: d.packets ?? [d.minPackets, d.q1, d.medianPackets, d.q3, d.maxPackets],
    name: d.type,
    type: 'box' as const,
    marker: { color: 'rgba(0, 212, 170, 0.6)' },
    line: { color: '#00d4aa' },
  }));

  const layout = {
    title: title ?? 'Packet Distribution by Attack Type',
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    font: { color: 'var(--ids-text)', family: 'JetBrains Mono, monospace' },
    margin: { t: 60, r: 40, b: 100, l: 60 },
    xaxis: {
      tickangle: -45,
      tickfont: { size: 10 },
      gridcolor: 'var(--ids-border)',
    },
    yaxis: {
      title: 'Packets',
      gridcolor: 'var(--ids-border)',
    },
    showlegend: false,
  };

  const config = { responsive: true, displayModeBar: true };

  return (
    <div className="w-full h-full min-h-[300px]">
      <Plot
        data={boxData}
        layout={layout}
        config={config}
        style={{ width: '100%', minHeight: 350 }}
        useResizeHandler
      />
    </div>
  );
}
