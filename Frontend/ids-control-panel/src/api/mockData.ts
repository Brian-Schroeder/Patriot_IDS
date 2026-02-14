import type { IntrusionAlert, TrafficStats, SeverityDistribution, AttackTypeStats } from '../types';
import { subHours, format } from 'date-fns';

export type TimeRange = '1h' | '6h' | '24h' | '7d';

function getTimeRangeHours(range: TimeRange): number {
  switch (range) {
    case '1h': return 1;
    case '6h': return 6;
    case '24h': return 24;
    case '7d': return 24 * 7;
    default: return 24;
  }
}

function filterAlertsByTimeRange(alerts: IntrusionAlert[], range: TimeRange): IntrusionAlert[] {
  const hours = getTimeRangeHours(range);
  const cutoff = subHours(new Date(), hours);
  return alerts.filter((a) => new Date(a.timestamp) >= cutoff);
}

export function getFilteredAlerts(timeRange: TimeRange = '24h'): IntrusionAlert[] {
  return filterAlertsByTimeRange(mockAlerts, timeRange);
}

const attackTypes = [
  'SQL Injection',
  'Port Scan',
  'DDoS',
  'Brute Force',
  'XSS',
  'Buffer Overflow',
  'DNS Tunneling',
  'Malware C2',
];

const severities = ['low', 'medium', 'high', 'critical'] as const;

function randomIp(): string {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

function generateAlerts(count: number): IntrusionAlert[] {
  const alerts: IntrusionAlert[] = [];
  const now = new Date();

  for (let i = 0; i < count; i++) {
    const ts = subHours(now, Math.random() * 72);
    const type = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];

    const packets = Math.floor(50 + Math.random() * 5000);
    const bytes = packets * (64 + Math.floor(Math.random() * 500));

    alerts.push({
      id: `alert-${i}-${Date.now()}`,
      timestamp: ts.toISOString(),
      severity,
      sourceIp: randomIp(),
      destIp: randomIp(),
      protocol: Math.random() > 0.5 ? 'TCP' : 'UDP',
      port: [80, 443, 22, 3306, 5432, 8080][Math.floor(Math.random() * 6)],
      attackType: type,
      packetCount: packets,
      bytesTransferred: bytes,
    });
  }

  return alerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

export const mockAlerts = generateAlerts(200);

export function getTrafficStats(timeRange: TimeRange = '24h'): TrafficStats[] {
  const now = new Date();
  const hours = getTimeRangeHours(timeRange);
  const bucketCount = Math.min(hours, 24);
  const bucketSize = hours / bucketCount;
  const stats: TrafficStats[] = [];
  const filteredAlerts = filterAlertsByTimeRange(mockAlerts, timeRange);

  for (let i = bucketCount - 1; i >= 0; i--) {
    const bucketStart = subHours(now, (i + 1) * bucketSize);
    const bucketEnd = subHours(now, i * bucketSize);
    const alertsInBucket = filteredAlerts.filter(
      (a) => { const t = new Date(a.timestamp); return t >= bucketStart && t < bucketEnd; }
    );

    const severityCounts: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const a of alertsInBucket) {
      severityCounts[a.severity]++;
    }

    stats.push({
      hour: bucketSize >= 24 ? format(bucketStart, 'MMM d') : format(bucketStart, 'HH:mm'),
      totalPackets: Math.floor(10000 + Math.random() * 50000) + alertsInBucket.length * 100,
      alerts: alertsInBucket.length,
      bytes: Math.floor(1000000 + Math.random() * 10000000),
      severityCounts,
    });
  }

  return stats;
}

export function getSeverityDistribution(timeRange: TimeRange = '24h'): SeverityDistribution[] {
  const filteredAlerts = filterAlertsByTimeRange(mockAlerts, timeRange);
  const counts = severities.reduce(
    (acc, s) => {
      acc[s] = filteredAlerts.filter((a) => a.severity === s).length;
      return acc;
    },
    {} as Record<string, number>
  );

  return Object.entries(counts).map(([severity, count]) => ({ severity, count }));
}

export function getAttackTypeStats(timeRange: TimeRange = '24h'): AttackTypeStats[] {
  const filteredAlerts = filterAlertsByTimeRange(mockAlerts, timeRange);
  const byType = new Map<string, IntrusionAlert[]>();

  for (const alert of filteredAlerts) {
    const arr = byType.get(alert.attackType) ?? [];
    arr.push(alert);
    byType.set(alert.attackType, arr);
  }

  return Array.from(byType.entries()).map(([type, alerts]) => {
    const packets = alerts.map((a) => a.packetCount).sort((a, b) => a - b);
    const n = packets.length;
    const sum = packets.reduce((a, b) => a + b, 0);
    const min = packets[0] ?? 0;
    const max = packets[n - 1] ?? 0;
    const median = packets[Math.floor(n / 2)] ?? 0;
    const q1 = packets[Math.floor(n * 0.25)] ?? 0;
    const q3 = packets[Math.floor(n * 0.75)] ?? 0;

    return {
      type,
      count: n,
      avgPackets: Math.round(sum / n),
      minPackets: min,
      maxPackets: max,
      medianPackets: median,
      q1,
      q3,
      packets,
    };
  });
}
