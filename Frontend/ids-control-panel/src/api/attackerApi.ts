/** Attack types that the attacker VM can execute - aligned with IDS detection rules */
export const ATTACK_TYPES = [
  'Port Scan',
  'DDoS',
  'Brute Force',
  'SQL Injection',
  'XSS',
  'Buffer Overflow',
  'DNS Tunneling',
  'Malware C2',
] as const;

export type AttackType = (typeof ATTACK_TYPES)[number];

const API_BASE = import.meta.env.VITE_API_URL ?? import.meta.env.VITE_ATTACKER_API_URL ?? '/api/v1';

export interface StartAttackResponse {
  success: boolean;
  message?: string;
  attackType?: string;
  attackId?: string;
}

export interface StartAttackParams {
  attackType: AttackType;
  attackerUrl: string;
  targetIp?: string;
}

/**
 * Trigger one batch of simulated live traffic. Poll every ~2s for live stream demo.
 */
export async function simulateLiveTick(): Promise<{ success: boolean; packets?: number; alerts?: number }> {
  const url = `${API_BASE.replace(/\/$/, '')}/demo/live-tick`;
  const res = await fetch(url, { method: 'POST' });
  const text = await res.text();
  let data: { success?: boolean; packets?: number; alerts?: number };
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }
  if (!res.ok) return { success: false };
  return { success: true, ...data };
}

/**
 * Simulate an attack for demo - no attacker VM needed.
 * Backend creates alerts and updates Packets Received to show IDS detection.
 */
export async function simulateAttack(
  attackType: AttackType,
  targetIp?: string
): Promise<{ success: boolean; alerts_created?: number; message?: string }> {
  const url = `${API_BASE.replace(/\/$/, '')}/demo/simulate-attack`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      attackType,
      ...(targetIp && { targetIp }),
    }),
  });

  const text = await res.text();
  let data: { success?: boolean; message?: string; error?: string; alerts_created?: number };
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }
  if (!res.ok) {
    const msg = (data?.error ?? data?.message ?? text) || `Request failed: ${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return { success: true, ...data } as { success: boolean; alerts_created?: number; message?: string };
}

/**
 * Signals the attacker VM to start an attack.
 * Backend proxies the command to the attacker at attackerUrl.
 */
export async function startAttack(
  attackType: AttackType,
  attackerUrl: string,
  targetIp?: string
): Promise<StartAttackResponse> {
  const url = `${API_BASE.replace(/\/$/, '')}/attack/start`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      attackType,
      attackerUrl,
      ...(targetIp && { targetIp }),
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    let body: StartAttackResponse | undefined;
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
    throw new Error(body?.message ?? `Request failed: ${res.status} ${res.statusText}`);
  }

  return res.json();
}

export interface ReceivedPacket {
  id: string;
  timestamp: string;
  sourceIp: string;
  destIp: string;
  protocol: string;
  port: number;
  size: number;
  attackType?: string;
}

/** Fetches packets received by the IDS (from traffic capture during attacks). */
export async function getReceivedPackets(): Promise<ReceivedPacket[]> {
  try {
    const url = `${API_BASE.replace(/\/$/, '')}/packets`;
    const res = await fetch(url);
    if (!res.ok) return [];
    const text = await res.text();
    if (!text.trim()) return [];
    const data = JSON.parse(text);
    return Array.isArray(data) ? data : (data.packets ?? data.data ?? []);
  } catch {
    return [];
  }
}
