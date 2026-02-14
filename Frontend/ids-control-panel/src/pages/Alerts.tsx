import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { mockAlerts } from '../api/mockData';
import { format, subHours } from 'date-fns';
import { Search, Filter, ChevronDown } from 'lucide-react';
import type { IntrusionAlert } from '../types';

const SEVERITIES = ['all', 'low', 'medium', 'high', 'critical'] as const;
const TIME_RANGES = [
  { value: 'all', label: 'All time' },
  { value: '1h', label: 'Last 1 hour' },
  { value: '6h', label: 'Last 6 hours' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
] as const;

export function Alerts() {
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('all');
  const [attackType, setAttackType] = useState<string>('all');
  const [protocol, setProtocol] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState('');
  const [destFilter, setDestFilter] = useState('');
  const [showFilters, setShowFilters] = useState(false);

  const { data: alerts } = useQuery({
    queryKey: ['allAlerts'],
    queryFn: () => mockAlerts,
  });

  const attackTypes = useMemo(() => {
    if (!alerts) return [];
    const set = new Set(alerts.map((a) => a.attackType));
    return ['all', ...Array.from(set).sort()];
  }, [alerts]);

  const filteredAlerts = useMemo(() => {
    if (!alerts) return [];
    let result = alerts;

    if (timeRange !== 'all') {
      const hours =
        timeRange === '1h' ? 1 : timeRange === '6h' ? 6 : timeRange === '24h' ? 24 : 168;
      const cutoff = subHours(new Date(), hours);
      result = result.filter((a) => new Date(a.timestamp) >= cutoff);
    }

    if (severity !== 'all') {
      result = result.filter((a) => a.severity === severity);
    }

    if (attackType !== 'all') {
      result = result.filter((a) => a.attackType === attackType);
    }

    if (protocol !== 'all') {
      result = result.filter((a) => a.protocol === protocol);
    }

    if (sourceFilter.trim()) {
      const q = sourceFilter.trim().toLowerCase();
      result = result.filter((a) => a.sourceIp.toLowerCase().includes(q));
    }

    if (destFilter.trim()) {
      const q = destFilter.trim().toLowerCase();
      result = result.filter((a) => a.destIp.toLowerCase().includes(q));
    }

    if (search.trim()) {
      const q = search.trim().toLowerCase();
      result = result.filter(
        (a) =>
          a.sourceIp.toLowerCase().includes(q) ||
          a.destIp.toLowerCase().includes(q) ||
          a.attackType.toLowerCase().includes(q) ||
          a.protocol.toLowerCase().includes(q) ||
          a.severity.toLowerCase().includes(q)
      );
    }

    return result;
  }, [alerts, search, severity, timeRange, attackType, protocol, sourceFilter, destFilter]);

  if (!alerts) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--ids-text-muted)]">
        Loading alerts...
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-[var(--ids-border)] flex flex-col sm:flex-row gap-4 items-stretch sm:items-center justify-between">
          <h3 className="text-lg font-semibold text-[var(--ids-text)]">
            All Alerts ({filteredAlerts.length}{' '}
            {filteredAlerts.length !== alerts.length && (
              <span className="text-[var(--ids-text-muted)] font-normal">
                of {alerts.length}
              </span>
            )}
            )
          </h3>
          <div className="flex flex-wrap gap-2 items-center">
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--ids-text-muted)]"
                strokeWidth={2}
              />
              <input
                type="text"
                placeholder="Search alerts..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-10 pr-4 py-2 rounded-lg bg-[var(--ids-bg)] border border-[var(--ids-border)] text-[var(--ids-text)] placeholder-[var(--ids-text-muted)] text-sm focus:outline-none focus:ring-2 focus:ring-[var(--ids-accent)] focus:border-transparent transition-all"
              />
            </div>
            <button
              onClick={() => setShowFilters((v) => !v)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                showFilters
                  ? 'bg-[var(--ids-accent)] text-[var(--ids-bg)]'
                  : 'bg-[var(--ids-border)]/50 text-[var(--ids-text-muted)] hover:bg-[var(--ids-border)] hover:text-[var(--ids-text)]'
              }`}
            >
              <Filter size={16} />
              Filters
              <ChevronDown
                size={14}
                className={`transition-transform ${showFilters ? 'rotate-180' : ''}`}
              />
            </button>
          </div>
        </div>

        {showFilters && (
          <div className="px-6 py-4 bg-[var(--ids-bg)]/50 border-b border-[var(--ids-border)] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
            <div>
              <label className="block text-xs font-medium text-[var(--ids-text-muted)] mb-1.5">
                Time
              </label>
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[var(--ids-surface)] border border-[var(--ids-border)] text-[var(--ids-text)] text-sm focus:outline-none focus:ring-2 focus:ring-[var(--ids-accent)]"
              >
                {TIME_RANGES.map(({ value, label }) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--ids-text-muted)] mb-1.5">
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[var(--ids-surface)] border border-[var(--ids-border)] text-[var(--ids-text)] text-sm focus:outline-none focus:ring-2 focus:ring-[var(--ids-accent)]"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--ids-text-muted)] mb-1.5">
                Type
              </label>
              <select
                value={attackType}
                onChange={(e) => setAttackType(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[var(--ids-surface)] border border-[var(--ids-border)] text-[var(--ids-text)] text-sm focus:outline-none focus:ring-2 focus:ring-[var(--ids-accent)]"
              >
                {attackTypes.map((t) => (
                  <option key={t} value={t}>
                    {t === 'all' ? 'All types' : t}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--ids-text-muted)] mb-1.5">
                Protocol
              </label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[var(--ids-surface)] border border-[var(--ids-border)] text-[var(--ids-text)] text-sm focus:outline-none focus:ring-2 focus:ring-[var(--ids-accent)]"
              >
                <option value="all">All</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--ids-text-muted)] mb-1.5">
                Source IP
              </label>
              <input
                type="text"
                placeholder="Filter by source..."
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[var(--ids-surface)] border border-[var(--ids-border)] text-[var(--ids-text)] placeholder-[var(--ids-text-muted)] text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[var(--ids-accent)]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--ids-text-muted)] mb-1.5">
                Destination IP
              </label>
              <input
                type="text"
                placeholder="Filter by dest..."
                value={destFilter}
                onChange={(e) => setDestFilter(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[var(--ids-surface)] border border-[var(--ids-border)] text-[var(--ids-text)] placeholder-[var(--ids-text-muted)] text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[var(--ids-accent)]"
              />
            </div>
          </div>
        )}

        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-[var(--ids-surface)] z-10">
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
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td
                    colSpan={9}
                    className="px-6 py-12 text-center text-[var(--ids-text-muted)]"
                  >
                    No alerts match your filters.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="border-b border-[var(--ids-border)]/50 hover:bg-[var(--ids-border)]/30 transition-colors"
                  >
                    <td className="px-6 py-3 text-[var(--ids-text-muted)] whitespace-nowrap">
                      {format(new Date(alert.timestamp), 'MMM d, yyyy HH:mm:ss')}
                    </td>
                    <td className="px-6 py-3">
                      <SeverityBadge severity={alert.severity} />
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
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function SeverityBadge({
  severity,
}: {
  severity: IntrusionAlert['severity'];
}) {
  const styles: Record<
    IntrusionAlert['severity'],
    { bg: string; text: string }
  > = {
    critical: { bg: 'bg-[var(--ids-danger)]/20', text: 'text-[var(--ids-danger)]' },
    high: { bg: 'bg-[var(--ids-severity-high)]/20', text: 'text-[var(--ids-severity-high)]' },
    medium: {
      bg: 'bg-[var(--ids-severity-medium)]/20',
      text: 'text-[var(--ids-severity-medium)]',
    },
    low: { bg: 'bg-[var(--ids-severity-low)]/20', text: 'text-[var(--ids-severity-low)]' },
  };
  const s = styles[severity];
  return (
    <span
      className={`px-2 py-0.5 rounded text-xs font-medium ${s.bg} ${s.text}`}
    >
      {severity}
    </span>
  );
}
