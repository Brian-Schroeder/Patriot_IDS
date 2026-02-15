import type {
  IntrusionAlert,
  TrafficStats,
  SeverityDistribution,
  AttackTypeStats,
} from '../types';

const API_BASE =
  import.meta.env.VITE_API_URL ??
  import.meta.env.VITE_ATTACKER_API_URL ??
  '/api/v1';

interface BackendAlert {
  id: string;
  alert_type: string;
  source_ip: string;
  destination_ip?: string;
  destination_port?: number;
  description: string;
  level: string;
  status: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

function mapAlert(a: BackendAlert): IntrusionAlert {
  const severity = (a.level?.toLowerCase() ?? 'medium') as IntrusionAlert['severity'];
  const packetCount =
    (a.metadata?.packet_count as number) ??
    (a.metadata?.connection_count as number) ??
    1;
  const bytesTransferred =
    (a.metadata?.bytes as number) ?? packetCount * 256;

  return {
    id: a.id,
    timestamp: a.timestamp,
    severity,
    sourceIp: a.source_ip,
    destIp: a.destination_ip ?? '0.0.0.0',
    protocol: 'TCP',
    port: a.destination_port ?? 0,
    attackType: a.alert_type,
    packetCount,
    bytesTransferred,
  };
}

export async function fetchAlerts(params?: {
  level?: string;
  status?: string;
  since?: string;
  limit?: number;
  offset?: number;
}): Promise<IntrusionAlert[]> {
  const search = new URLSearchParams();
  if (params?.level) search.set('level', params.level);
  if (params?.status) search.set('status', params.status);
  if (params?.since) search.set('since', params.since);
  if (params?.limit) search.set('limit', String(params.limit));
  if (params?.offset) search.set('offset', String(params.offset));

  const url = `${API_BASE.replace(/\/$/, '')}/alerts${search.toString() ? `?${search}` : ''}`;
  const res = await fetch(url);
  if (!res.ok) return [];
  const text = await res.text();
  let data: { alerts?: BackendAlert[] };
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    return [];
  }
  return (data.alerts ?? []).map(mapAlert);
}

export async function fetchDashboardSummary(): Promise<{
  alerts: {
    last_hour: number;
    last_24h: number;
    by_severity: Record<string, number>;
    by_status?: Record<string, number>;
    unacknowledged?: number;
  };
  threats: {
    top_attackers: { ip: string; count: number }[];
    top_alert_types: { type: string; count: number }[];
    recent_critical: BackendAlert[];
  };
}> {
  const url = `${API_BASE.replace(/\/$/, '')}/dashboard/summary`;
  const res = await fetch(url);
  const text = await res.text();
  if (!res.ok) throw new Error(text || `Failed to fetch dashboard: ${res.status}`);
  try {
    const data = (text ? JSON.parse(text) : {}) as {
      alerts?: {
        last_hour?: number;
        last_24h?: number;
        by_severity?: Record<string, number>;
        by_status?: Record<string, number>;
        unacknowledged?: number;
      };
      threats?: {
        top_attackers?: { ip: string; count: number }[];
        top_alert_types?: { type: string; count: number }[];
        recent_critical?: BackendAlert[];
      };
    };
    const alerts = data.alerts ?? {};
    const threats = data.threats ?? {};
    return {
      alerts: {
        last_hour: alerts.last_hour ?? 0,
        last_24h: alerts.last_24h ?? 0,
        by_severity: alerts.by_severity ?? { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
        by_status: alerts.by_status,
        unacknowledged: alerts.unacknowledged,
      },
      threats: {
        top_attackers: threats.top_attackers ?? [],
        top_alert_types: threats.top_alert_types ?? [],
        recent_critical: threats.recent_critical ?? [],
      },
    };
  } catch {
    throw new Error('Invalid response from server');
  }
}

export type ChartTimeRange = '1m' | '5m' | '15m' | '30m' | '1h' | '24h';

function getSinceFromTimeRange(timeRange: ChartTimeRange): string {
  const minutesMap: Record<ChartTimeRange, number> = {
    '1m': 1,
    '5m': 5,
    '15m': 15,
    '30m': 30,
    '1h': 60,
    '24h': 1440,
  };
  const minutes = minutesMap[timeRange];
  return new Date(Date.now() - minutes * 60 * 1000).toISOString();
}

export async function getAlertsFromApi(
  timeRange?: ChartTimeRange
): Promise<IntrusionAlert[]> {
  const since = getSinceFromTimeRange(timeRange ?? '5m');
  return fetchAlerts({ limit: 1000, since });
}

/** Traffic stats for charts - derived from timeline (drives X-axis) */
export async function getTrafficStatsFromApi(
  timeRange: ChartTimeRange = '5m'
): Promise<TrafficStats[]> {
  const isMinutes = ['1m', '5m', '15m', '30m'].includes(timeRange);

  type TimelineItem = {
    timestamp: string;
    total: number;
    low: number;
    medium: number;
    high: number;
    critical: number;
  };

  if (isMinutes) {
    const minutesMap = { '1m': 1, '5m': 5, '15m': 15, '30m': 30 };
    const minutes = minutesMap[timeRange as keyof typeof minutesMap];
    const interval = minutes <= 1 ? 1 : minutes <= 5 ? 1 : minutes <= 15 ? 1 : 2;
    const url = `${API_BASE.replace(/\/$/, '')}/dashboard/timeline?minutes=${minutes}&interval=${interval}&max_points=12`;
    const res = await fetch(url);
    if (!res.ok) return [];
    const text = await res.text();
    let data: { timeline?: TimelineItem[] };
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      return [];
    }
    const timeline = data.timeline ?? [];
    return timeline.map((t) => {
      const d = new Date(t.timestamp);
      const hour = d.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: minutes <= 5 ? '2-digit' : undefined,
      });
      return {
        hour,
        totalPackets: t.total * 50,
        alerts: t.total,
        bytes: t.total * 1024,
        severityCounts: {
          low: t.low,
          medium: t.medium,
          high: t.high,
          critical: t.critical,
        },
      };
    });
  }

  const hours = timeRange === '1h' ? 1 : 24;
  const url = `${API_BASE.replace(/\/$/, '')}/dashboard/timeline?hours=${hours}&max_points=12`;
  const res = await fetch(url);
  if (!res.ok) return [];
  const text = await res.text();
  let data: { timeline?: TimelineItem[] };
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    return [];
  }
  const timeline = data.timeline ?? [];
  return timeline.map((t) => {
    const d = new Date(t.timestamp);
    const hour = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    return {
      hour,
      totalPackets: t.total * 50,
      alerts: t.total,
      bytes: t.total * 1024,
      severityCounts: {
        low: t.low,
        medium: t.medium,
        high: t.high,
        critical: t.critical,
      },
    };
  });
}

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'] as const;

/** Severity distribution from alerts */
export async function getSeverityDistributionFromApi(
  timeRange: ChartTimeRange = '5m'
): Promise<SeverityDistribution[]> {
  const since = getSinceFromTimeRange(timeRange);
  const alerts = await fetchAlerts({ limit: 5000, since });

  const counts: Record<string, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const a of alerts) {
    const sev = ((a.severity ?? 'medium') + '').toLowerCase();
    const key = SEVERITY_ORDER.includes(sev as (typeof SEVERITY_ORDER)[number]) ? sev : 'medium';
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    count: counts[severity] ?? 0,
  }));
}

/** Attack type stats from alerts */
export async function getAttackTypeStatsFromApi(
  timeRange: ChartTimeRange = '5m'
): Promise<AttackTypeStats[]> {
  const since = getSinceFromTimeRange(timeRange);
  const alerts = await fetchAlerts({ limit: 5000, since });

  const byType = new Map<string, IntrusionAlert[]>();
  for (const a of alerts) {
    const arr = byType.get(a.attackType) ?? [];
    arr.push(a);
    byType.set(a.attackType, arr);
  }

  return Array.from(byType.entries()).map(([type, alertList]) => {
    const packets = alertList.map((a) => a.packetCount).sort((a, b) => a - b);
    const n = packets.length;
    const sum = packets.reduce((a, b) => a + b, 0);
    return {
      type,
      count: n,
      avgPackets: n ? Math.round(sum / n) : 0,
      minPackets: packets[0] ?? 0,
      maxPackets: packets[n - 1] ?? 0,
      medianPackets: packets[Math.floor(n / 2)] ?? 0,
      q1: packets[Math.floor(n * 0.25)] ?? 0,
      q3: packets[Math.floor(n * 0.75)] ?? 0,
      packets,
    };
  });
}
