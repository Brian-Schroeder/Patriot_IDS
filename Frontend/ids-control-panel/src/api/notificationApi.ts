const API_BASE = import.meta.env.VITE_API_URL ?? import.meta.env.VITE_ATTACKER_API_URL ?? '/api/v1';

export interface TestNotificationResponse {
  success: boolean;
  message?: string;
}

/**
 * Sends a test alert to the SNS topic. Email subscribers are configured in AWS.
 */
export async function sendTestNotification(): Promise<TestNotificationResponse> {
  const res = await fetch(`${API_BASE.replace(/\/$/, '')}/notifications/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });

  if (!res.ok) {
    const text = await res.text();
    try {
      const data = JSON.parse(text);
      throw new Error(data?.message ?? data?.error ?? `Request failed: ${res.status}`);
    } catch (e) {
      if (e instanceof Error && e.message.startsWith('Request failed')) throw e;
      throw new Error(`Request failed: ${res.status} ${res.statusText}`);
    }
  }

  return res.json();
}
