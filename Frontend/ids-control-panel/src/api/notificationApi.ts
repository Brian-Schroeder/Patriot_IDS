const API_BASE = import.meta.env.VITE_ATTACKER_API_URL ?? '/api';

export interface TestNotificationResponse {
  success: boolean;
  message?: string;
}

/**
 * Sends a test email notification to the specified recipients.
 */
export async function sendTestEmail(emails: string[]): Promise<TestNotificationResponse> {
  const url = `${API_BASE.replace(/\/$/, '')}/notifications/test/email`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ emails }),
  });

  if (!res.ok) {
    const text = await res.text();
    try {
      const data = JSON.parse(text);
      throw new Error(data?.message ?? `Request failed: ${res.status}`);
    } catch (e) {
      if (e instanceof Error && e.message.startsWith('Request failed')) throw e;
      throw new Error(`Request failed: ${res.status} ${res.statusText}`);
    }
  }

  return res.json();
}

/**
 * Sends a test SMS notification to the specified recipients.
 */
export async function sendTestSms(phones: string[]): Promise<TestNotificationResponse> {
  const url = `${API_BASE.replace(/\/$/, '')}/notifications/test/sms`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phones }),
  });

  if (!res.ok) {
    const text = await res.text();
    try {
      const data = JSON.parse(text);
      throw new Error(data?.message ?? `Request failed: ${res.status}`);
    } catch (e) {
      if (e instanceof Error && e.message.startsWith('Request failed')) throw e;
      throw new Error(`Request failed: ${res.status} ${res.statusText}`);
    }
  }

  return res.json();
}
