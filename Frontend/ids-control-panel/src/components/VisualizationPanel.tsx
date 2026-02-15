import { useEffect } from 'react';
import { useChartStore } from '../store/chartStore';
import { useQuery, keepPreviousData } from '@tanstack/react-query';

const LIVE_TICK_INTERVAL_MS = 2000;
import {
  getTrafficStatsFromApi,
  getSeverityDistributionFromApi,
  getAlertsFromApi,
} from '../api/alertsApi';
import { ChartSelector } from './ChartSelector';
import { BarChart } from './charts/BarChart';
import { LineChartComponent } from './charts/LineChart';
import { DotPlot } from './charts/DotPlot';
import { PieChartComponent } from './charts/PieChart';

const VALID_CHART_TYPES = ['bar', 'line', 'dotplot', 'pie'] as const;

export function VisualizationPanel() {
  const { chartType, timeRange, setChartType } = useChartStore();
  const effectiveChartType = VALID_CHART_TYPES.includes(chartType as (typeof VALID_CHART_TYPES)[number])
    ? chartType
    : 'bar';

  useEffect(() => {
    if (effectiveChartType !== chartType) {
      setChartType('bar');
    }
  }, [chartType, effectiveChartType, setChartType]);

  const { data: trafficStats = [] } = useQuery({
    queryKey: ['trafficStats', timeRange],
    queryFn: () => getTrafficStatsFromApi(timeRange),
    retry: 1,
    refetchInterval: LIVE_TICK_INTERVAL_MS,
    placeholderData: keepPreviousData,
  });

  const { data: severityDist = [] } = useQuery({
    queryKey: ['severityDistribution', timeRange],
    queryFn: () => getSeverityDistributionFromApi(timeRange),
    retry: 1,
    refetchInterval: LIVE_TICK_INTERVAL_MS,
    placeholderData: keepPreviousData,
  });

  const { data: filteredAlerts = [] } = useQuery({
    queryKey: ['filteredAlerts', timeRange],
    queryFn: () => getAlertsFromApi(timeRange),
    retry: 1,
    refetchInterval: LIVE_TICK_INTERVAL_MS,
    placeholderData: keepPreviousData,
  });

  const renderChart = () => {
    switch (effectiveChartType) {
      case 'bar':
        return (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <BarChart
              data={trafficStats}
              dataKey="hour"
              valueKey="alerts"
              title="Alerts Over Time"
              variant="alertsByHour"
              xAxisLabel="Time"
              yAxisLabel="Alerts"
            />
            <BarChart
              data={severityDist}
              dataKey="severity"
              valueKey="count"
              title="Severity Distribution"
              variant="severity"
              xAxisLabel="Severity"
              yAxisLabel="Count"
            />
          </div>
        );
      case 'line':
        return <LineChartComponent data={trafficStats} title="Traffic & Alerts Over Time" />;
      case 'dotplot':
        return <DotPlot data={filteredAlerts} title="Alerts: Packets vs Time" />;
      case 'pie':
        return <PieChartComponent data={severityDist.filter((s) => s.count > 0)} title="Alert Severity Breakdown" />;
      default:
        return null;
    }
  };

  return (
    <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] shadow-sm overflow-hidden">
      <div className="p-5 border-b border-[var(--ids-border)]">
        <ChartSelector />
      </div>
      <div className="p-6 min-h-[560px]">
        {renderChart()}
      </div>
    </div>
  );
}
