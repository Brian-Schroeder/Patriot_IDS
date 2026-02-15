import { Link } from 'react-router-dom';
import { VisualizationPanel } from '../components/VisualizationPanel';
import { useQuery } from '@tanstack/react-query';
import { fetchAlerts, fetchDashboardSummary } from '../api/alertsApi';
import { format } from 'date-fns';
import { AlertTriangle, ShieldCheck, Activity } from 'lucide-react';

export function Dashboard() {
  const { data: summary, isError: summaryError } = useQuery({
    queryKey: ['dashboardSummary'],
    queryFn: fetchDashboardSummary,
    retry: 1,
    refetchInterval: 3000,
  });

  const { data: alerts = [] } = useQuery({
    queryKey: ['alerts', 'recent'],
    queryFn: () => fetchAlerts({ limit: 10 }),
    retry: 1,
    refetchInterval: 3000,
  });

  const criticalCount = summary?.alerts?.by_severity?.CRITICAL ?? 0;
  const highCount = summary?.alerts?.by_severity?.HIGH ?? 0;
  const totalCount = summary?.alerts?.last_24h ?? alerts.length;

  return (
    <div className="space-y-8">
      {summaryError && (
        <div className="rounded-xl bg-amber-500/20 border border-amber-500/50 p-4 text-amber-400">
          <p className="font-medium">Backend not connected</p>
          <p className="text-sm mt-1">
            Start the backend with: <code className="bg-black/30 px-1 rounded">cd Backend/ids_backend && python run.py</code>
          </p>
        </div>
      )}
      {!summaryError && (
        <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/30 p-3 text-center text-sm text-emerald-400">
          Live stream: Dashboard polls /demo/live-tick every 2s — graphs update from stream data
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] p-5 shadow-sm transition-shadow hover:shadow-md">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[var(--ids-accent)]/20">
              <Activity className="w-5 h-5 text-[var(--ids-accent)]" />
            </div>
            <div>
              <p className="text-sm text-[var(--ids-text-muted)]">Total Alerts (24h)</p>
              <p className="text-2xl font-bold text-[var(--ids-text)]">{totalCount}</p>
            </div>
          </div>
        </div>
        <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] p-5 shadow-sm transition-shadow hover:shadow-md">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[var(--ids-warn)]/20">
              <AlertTriangle className="w-5 h-5 text-[var(--ids-warn)]" />
            </div>
            <div>
              <p className="text-sm text-[var(--ids-text-muted)]">High Severity</p>
              <p className="text-2xl font-bold text-[var(--ids-text)]">{highCount}</p>
            </div>
          </div>
        </div>
        <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] p-5 shadow-sm transition-shadow hover:shadow-md">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[var(--ids-danger)]/20">
              <ShieldCheck className="w-5 h-5 text-[var(--ids-danger)]" />
            </div>
            <div>
              <p className="text-sm text-[var(--ids-text-muted)]">Critical</p>
              <p className="text-2xl font-bold text-[var(--ids-text)]">{criticalCount}</p>
            </div>
          </div>
        </div>
      </div>

      <VisualizationPanel />

      {alerts && alerts.length > 0 ? (
        <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] overflow-hidden shadow-sm">
          <h3 className="px-6 py-4 text-lg font-semibold border-b border-[var(--ids-border)]">
            Recent Alerts
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--ids-border)]">
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Time
                  </th>
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Severity
                  </th>
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Type
                  </th>
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Source
                  </th>
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Dest
                  </th>
                  <th className="text-right px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Packets
                  </th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="border-b border-[var(--ids-border)]/50 hover:bg-[var(--ids-border)]/30"
                  >
                    <td className="px-6 py-3 text-[var(--ids-text-muted)]">
                      {format(new Date(alert.timestamp), 'MMM d, HH:mm:ss')}
                    </td>
                    <td className="px-6 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-medium ${
                          alert.severity === 'critical'
                            ? 'bg-[var(--ids-danger)]/20 text-[var(--ids-danger)]'
                            : alert.severity === 'high'
                              ? 'bg-orange-500/20 text-orange-400'
                              : alert.severity === 'medium'
                                ? 'bg-[var(--ids-warn)]/20 text-[var(--ids-warn)]'
                                : 'bg-[var(--ids-accent)]/20 text-[var(--ids-accent)]'
                        }`}
                      >
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-[var(--ids-text)]">{alert.attackType ?? '—'}</td>
                    <td className="px-6 py-3 font-mono text-[var(--ids-text-muted)] text-xs">
                      {alert.sourceIp}
                    </td>
                    <td className="px-6 py-3 font-mono text-[var(--ids-text-muted)] text-xs">
                      {alert.destIp}
                    </td>
                    <td className="px-6 py-3 text-right text-[var(--ids-text)]">
                      {alert.packetCount}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] p-12 text-center">
          <p className="text-[var(--ids-text-muted)]">No alerts yet.</p>
          <p className="text-sm text-[var(--ids-text-muted)] mt-1">
            Go to <Link to="/testing" className="text-[var(--ids-accent)] hover:underline">Testing</Link> and click an attack button (Demo Mode) to simulate IDS detections.
          </p>
        </div>
      )}
    </div>
  );
}
