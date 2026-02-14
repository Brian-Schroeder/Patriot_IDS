import { useQuery } from '@tanstack/react-query';
import { mockAlerts } from '../api/mockData';
import { format } from 'date-fns';

export function Alerts() {
  const { data: alerts } = useQuery({
    queryKey: ['allAlerts'],
    queryFn: () => mockAlerts,
  });

  if (!alerts) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--ids-text-muted)]">
        Loading alerts...
      </div>
    );
  }

  return (
    <div className="rounded-lg bg-[var(--ids-surface)] border border-[var(--ids-border)] overflow-hidden">
      <h3 className="px-6 py-4 text-lg font-semibold border-b border-[var(--ids-border)]">
        All Alerts ({alerts.length})
      </h3>
      <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-[var(--ids-surface)]">
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
                Protocol
              </th>
              <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                Source
              </th>
              <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                Dest
              </th>
              <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                Port
              </th>
              <th className="text-right px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                Packets
              </th>
              <th className="text-right px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                Bytes
              </th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr
                key={alert.id}
                className="border-b border-[var(--ids-border)]/50 hover:bg-[var(--ids-border)]/30"
              >
                <td className="px-6 py-3 text-[var(--ids-text-muted)] whitespace-nowrap">
                  {format(new Date(alert.timestamp), 'MMM d, yyyy HH:mm:ss')}
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
                <td className="px-6 py-3 text-[var(--ids-text)]">{alert.attackType}</td>
                <td className="px-6 py-3 text-[var(--ids-text-muted)]">{alert.protocol}</td>
                <td className="px-6 py-3 font-mono text-[var(--ids-text-muted)] text-xs">
                  {alert.sourceIp}
                </td>
                <td className="px-6 py-3 font-mono text-[var(--ids-text-muted)] text-xs">
                  {alert.destIp}
                </td>
                <td className="px-6 py-3 text-[var(--ids-text-muted)]">{alert.port}</td>
                <td className="px-6 py-3 text-right text-[var(--ids-text)]">
                  {alert.packetCount.toLocaleString()}
                </td>
                <td className="px-6 py-3 text-right text-[var(--ids-text-muted)]">
                  {alert.bytesTransferred.toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
