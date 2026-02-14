/** Attack types that the attacker VM can execute */
export const ATTACK_TYPES = [
  'SQL Injection',
  'Port Scan',
  'DDoS',
  'Brute Force',
  'XSS',
  'Buffer Overflow',
  'DNS Tunneling',
  'Malware C2',
] as const;

export type AttackType = (typeof ATTACK_TYPES)[number];

const API_BASE = import.meta.env.VITE_ATTACKER_API_URL ?? '/api';

export interface StartAttackResponse {
  success: boolean;
  message?: string;
  attackType?: string;
  attackId?: string;
}

/**
 * Signals the attacker VM to start an attack of the specified type.
 * Sends POST to /api/attack/start (or VITE_ATTACKER_API_URL if set).
 */
export async function startAttack(attackType: AttackType): Promise<StartAttackResponse> {
  const url = `${API_BASE.replace(/\/$/, '')}/attack/start`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attackType }),
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

/** Fetches packets being received (e.g. from attack stream). */
export async function getReceivedPackets(): Promise<ReceivedPacket[]> {
  try {
    const url = `${API_BASE.replace(/\/$/, '')}/packets`;
    const res = await fetch(url);
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}
