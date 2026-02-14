import { useChartStore } from '../store/chartStore';
import { useQuery } from '@tanstack/react-query';
import {
  getTrafficStats,
  getSeverityDistribution,
  getAttackTypeStats,
  getFilteredAlerts,
} from '../api/mockData';
import { BarChart } from './charts/BarChart';
import { LineChartComponent } from './charts/LineChart';
import { DotPlot } from './charts/DotPlot';
import { BoxPlot } from './charts/BoxPlot';
import { PieChartComponent } from './charts/PieChart';

export function VisualizationPanel() {
  const { chartType, timeRange } = useChartStore();

  const { data: trafficStats } = useQuery({
    queryKey: ['trafficStats', timeRange],
    queryFn: () => getTrafficStats(timeRange),
  });

  const { data: severityDist } = useQuery({
    queryKey: ['severityDistribution', timeRange],
    queryFn: () => getSeverityDistribution(timeRange),
  });

  const { data: attackTypeStats } = useQuery({
    queryKey: ['attackTypeStats', timeRange],
    queryFn: () => getAttackTypeStats(timeRange),
  });

  const { data: filteredAlerts } = useQuery({
    queryKey: ['filteredAlerts', timeRange],
    queryFn: () => getFilteredAlerts(timeRange),
  });

  if (!trafficStats || !severityDist || !attackTypeStats || !filteredAlerts) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--ids-text-muted)]">
        Loading visualization data...
      </div>
    );
  }

  const renderChart = () => {
    switch (chartType) {
      case 'bar':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <BarChart
              data={trafficStats}
              dataKey="hour"
              valueKey="alerts"
              title="Alerts by Hour"
            />
            <BarChart
              data={severityDist}
              dataKey="severity"
              valueKey="count"
              title="Severity Distribution"
              variant="severity"
            />
          </div>
        );
      case 'line':
        return <LineChartComponent data={trafficStats} title="Traffic & Alerts Over Time" />;
      case 'dotplot':
        return <DotPlot data={filteredAlerts} title="Alerts: Packets vs Time" />;
      case 'boxplot':
        return (
          <BoxPlot
            data={attackTypeStats}
            title="Packet Distribution by Attack Type"
          />
        );
      case 'pie':
        return <PieChartComponent data={severityDist} title="Alert Severity Breakdown" />;
      default:
        return null;
    }
  };

  return (
    <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] p-6 shadow-sm">
      {renderChart()}
    </div>
  );
}
