import { useMutation } from '@tanstack/react-query';
import { Mail, Send, Loader2 } from 'lucide-react';
import { sendTestNotification } from '../api/notificationApi';

export function NotificationCenter() {
  const testMutation = useMutation({
    mutationFn: sendTestNotification,
  });

  return (
    <div className="space-y-8">
      <p className="text-sm text-[var(--ids-text-muted)]">
        Alerts are sent via AWS SNS to the <code className="text-[var(--ids-accent)]">nids-alerts</code> topic.
        Email subscribers are configured in the AWS Console.
      </p>

      <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-[var(--ids-border)] flex items-center justify-between">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Mail className="w-5 h-5 text-[var(--ids-accent)]" />
            Test Notification
          </h3>
          <button
            type="button"
            onClick={() => testMutation.mutate()}
            disabled={testMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-emerald-600 text-white hover:bg-emerald-500 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
          >
            {testMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
            Send Test Alert
          </button>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-sm text-[var(--ids-text-muted)]">
            Click to send a test alert to all subscribers of the SNS topic. This verifies that
            notifications are working.
          </p>
          {(testMutation.isError || (testMutation.isSuccess && testMutation.data?.success === false)) && (
            <p className="text-sm text-[var(--ids-danger)]">
              {testMutation.error instanceof Error ? testMutation.error.message : testMutation.data?.message ?? 'Request failed'}
            </p>
          )}
          {testMutation.isSuccess && testMutation.data?.success !== false && (
            <p className="text-sm text-emerald-500">{testMutation.data?.message ?? 'Test sent successfully.'}</p>
          )}
        </div>
      </div>
    </div>
  );
}
