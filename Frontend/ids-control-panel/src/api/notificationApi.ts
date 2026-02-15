const API_BASE = import.meta.env.DEV
  ? '/api/v1'
  : (import.meta.env.VITE_API_URL ?? import.meta.env.VITE_ATTACKER_API_URL ?? '/api/v1');

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

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data?.message ?? data?.error ?? `Request failed: ${res.status}`);
  }
  // Backend returns 200 with success/message; success: false means AWS/config error
  if (data.success === false && data.message) {
    throw new Error(data.message);
  }
  return data;
}
