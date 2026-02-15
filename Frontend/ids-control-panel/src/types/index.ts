export type ChartType = 'dotplot' | 'bar' | 'line' | 'pie';

export interface IntrusionAlert {
  id: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  sourceIp: string;
  destIp: string;
  protocol: string;
  port: number;
  attackType: string;
  packetCount: number;
  bytesTransferred: number;
}

export interface TrafficStats {
  hour: string;
  totalPackets: number;
  alerts: number;
  bytes: number;
  /** Per-bucket severity counts for mixed bar colors (low, medium, high, critical) */
  severityCounts?: Record<string, number>;
}

export interface SeverityDistribution {
  severity: string;
  count: number;
}

export interface AttackTypeStats {
  type: string;
  count: number;
  avgPackets: number;
  minPackets: number;
  maxPackets: number;
  medianPackets: number;
  q1: number;
  q3: number;
  packets?: number[];
}
