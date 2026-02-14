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
    return res.json();
  } catch {
    return [];
  }
}
