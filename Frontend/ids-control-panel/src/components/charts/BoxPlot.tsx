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

  const textColor = '#e2e8f0';
  const gridColor = '#1e2a42';
  const layout = {
    title: title ?? 'Packet Distribution by Attack Type',
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    font: { color: textColor, family: 'JetBrains Mono, monospace', size: 12 },
    margin: { t: 60, r: 40, b: 100, l: 60 },
    titlefont: { color: textColor, size: 16 },
    xaxis: {
      title: 'Attack Type',
      titlefont: { color: textColor },
      tickangle: -45,
      tickfont: { size: 11, color: textColor },
      gridcolor: gridColor,
      zerolinecolor: gridColor,
      linecolor: gridColor,
      color: textColor,
    },
    yaxis: {
      title: 'Packets',
      titlefont: { color: textColor },
      tickfont: { size: 11, color: textColor },
      gridcolor: gridColor,
      zerolinecolor: gridColor,
      linecolor: gridColor,
      color: textColor,
    },
    showlegend: false,
  };

  const config = { responsive: true, displayModeBar: true };

  return (
    <div className="w-full h-full min-h-[450px]">
      <Plot
        data={boxData}
        layout={layout}
        config={config}
        style={{ width: '100%', minHeight: 420 }}
        useResizeHandler
      />
    </div>
  );
}
