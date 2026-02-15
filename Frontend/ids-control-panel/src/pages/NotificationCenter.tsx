import { useState, useEffect } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Mail, MessageSquare, Plus, X, Send, Loader2 } from 'lucide-react';
import {
  sendTestEmail,
  sendTestSms,
  getNotificationRecipients,
  saveNotificationRecipients,
} from '../api/notificationApi';

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function isValidPhone(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  return digits.length >= 10;
}

export function NotificationCenter() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['notificationRecipients'],
    queryFn: getNotificationRecipients,
  });
  const [emails, setEmails] = useState<string[]>([]);
  const [phones, setPhones] = useState<string[]>([]);
  const [emailInput, setEmailInput] = useState('');
  const [phoneInput, setPhoneInput] = useState('');
  const [emailError, setEmailError] = useState('');
  const [phoneError, setPhoneError] = useState('');

  useEffect(() => {
    if (data) {
      setEmails(data.emails ?? []);
      setPhones(data.phones ?? []);
    }
  }, [data]);

  const saveMutation = useMutation({
    mutationFn: saveNotificationRecipients,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['notificationRecipients'] }),
  });

  const persistRecipients = (newEmails: string[], newPhones: string[]) => {
    saveMutation.mutate({ emails: newEmails, phones: newPhones });
  };

  const addEmail = () => {
    const trimmed = emailInput.trim().toLowerCase();
    setEmailError('');
    if (!trimmed) return;
    if (!isValidEmail(trimmed)) {
      setEmailError('Please enter a valid email address');
      return;
    }
    if (emails.includes(trimmed)) {
      setEmailError('This email is already added');
      return;
    }
    const newEmails = [...emails, trimmed];
    setEmails(newEmails);
    setEmailInput('');
    persistRecipients(newEmails, phones);
  };

  const removeEmail = (email: string) => {
    const newEmails = emails.filter((e) => e !== email);
    setEmails(newEmails);
    persistRecipients(newEmails, phones);
  };

  const addPhone = () => {
    const trimmed = phoneInput.trim();
    setPhoneError('');
    if (!trimmed) return;
    if (!isValidPhone(trimmed)) {
      setPhoneError('Please enter a valid phone number (at least 10 digits)');
      return;
    }
    const normalized = trimmed.replace(/\D/g, '');
    const formatted =
      normalized.length === 10
        ? `+1 ${normalized.slice(0, 3)}-${normalized.slice(3, 6)}-${normalized.slice(6)}`
        : `+${normalized}`;
    if (phones.some((p) => p.replace(/\D/g, '') === normalized)) {
      setPhoneError('This number is already added');
      return;
    }
    const newPhones = [...phones, formatted];
    setPhones(newPhones);
    setPhoneInput('');
    persistRecipients(emails, newPhones);
  };

  const removePhone = (phone: string) => {
    const newPhones = phones.filter((p) => p !== phone);
    setPhones(newPhones);
    persistRecipients(emails, newPhones);
  };

  const emailTest = useMutation({
    mutationFn: (recipients: string[]) => sendTestEmail(recipients),
  });

  const smsTest = useMutation({
    mutationFn: (recipients: string[]) => sendTestSms(recipients),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-[var(--ids-accent)]" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <p className="text-sm text-[var(--ids-text-muted)]">
        Add contacts below to receive alerts for critical and high-severity threats. Recipients are
        stored in the backend and used for SNS/SES notifications.
      </p>

      <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-[var(--ids-border)] flex items-center justify-between">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Mail className="w-5 h-5 text-[var(--ids-accent)]" />
            Email Recipients
          </h3>
          {emails.length > 0 && (
            <button
              type="button"
              onClick={() => emailTest.mutate(emails)}
              disabled={emailTest.isPending}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium bg-emerald-600 text-white hover:bg-emerald-500 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
            >
              {emailTest.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              Test All
            </button>
          )}
        </div>
        <div className="p-6 space-y-4">
          <div className="flex gap-2">
            <input
              type="email"
              value={emailInput}
              onChange={(e) => {
                setEmailInput(e.target.value);
                setEmailError('');
              }}
              onKeyDown={(e) => e.key === 'Enter' && addEmail()}
              placeholder="email@example.com"
              className="flex-1 max-w-md rounded-lg border border-[var(--ids-border)] bg-[var(--ids-bg)] px-4 py-2.5 text-[var(--ids-text)] placeholder:text-[var(--ids-text-muted)]/60 focus:border-[var(--ids-accent)] focus:ring-1 focus:ring-[var(--ids-accent)] focus:outline-none"
            />
            <button
              type="button"
              onClick={addEmail}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[var(--ids-accent)] text-white font-medium hover:opacity-90 transition-opacity"
            >
              <Plus className="w-4 h-4" />
              Add
            </button>
          </div>
          {emailError && (
            <p className="text-sm text-[var(--ids-danger)]">{emailError}</p>
          )}
          {emails.length > 0 ? (
            <ul className="space-y-2">
              {emails.map((email) => (
                <li
                  key={email}
                  className="flex items-center justify-between py-2 px-3 rounded-lg bg-[var(--ids-bg)] border border-[var(--ids-border)]/50 gap-2"
                >
                  <span className="text-[var(--ids-text)] flex-1 min-w-0 truncate">{email}</span>
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      type="button"
                      onClick={() => emailTest.mutate([email])}
                      disabled={emailTest.isPending}
                      className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
                      title="Send test email"
                    >
                      {emailTest.isPending ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Send className="w-3.5 h-3.5" />
                      )}
                      Test
                    </button>
                    <button
                      type="button"
                      onClick={() => removeEmail(email)}
                      className="p-1 rounded text-[var(--ids-text-muted)] hover:text-[var(--ids-danger)] hover:bg-[var(--ids-danger)]/10 transition-colors"
                      aria-label={`Remove ${email}`}
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-[var(--ids-text-muted)] py-4">
              No email addresses added. Add recipients to receive critical and high-severity alerts.
            </p>
          )}
          {emailTest.isError && (
            <p className="text-sm text-[var(--ids-danger)]">
              Test failed: {emailTest.error instanceof Error ? emailTest.error.message : 'Unknown error'}
            </p>
          )}
          {emailTest.isSuccess && (
            <p className="text-sm text-emerald-500">Test email sent successfully.</p>
          )}
        </div>
      </div>

      <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-[var(--ids-border)] flex items-center justify-between">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <MessageSquare className="w-5 h-5 text-[var(--ids-accent)]" />
            SMS Recipients
          </h3>
          {phones.length > 0 && (
            <button
              type="button"
              onClick={() => smsTest.mutate(phones)}
              disabled={smsTest.isPending}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium bg-emerald-600 text-white hover:bg-emerald-500 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
            >
              {smsTest.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              Test All
            </button>
          )}
        </div>
        <div className="p-6 space-y-4">
          <div className="flex gap-2">
            <input
              type="tel"
              value={phoneInput}
              onChange={(e) => {
                setPhoneInput(e.target.value);
                setPhoneError('');
              }}
              onKeyDown={(e) => e.key === 'Enter' && addPhone()}
              placeholder="(555) 123-4567 or +1 5551234567"
              className="flex-1 max-w-md rounded-lg border border-[var(--ids-border)] bg-[var(--ids-bg)] px-4 py-2.5 text-[var(--ids-text)] placeholder:text-[var(--ids-text-muted)]/60 focus:border-[var(--ids-accent)] focus:ring-1 focus:ring-[var(--ids-accent)] focus:outline-none"
            />
            <button
              type="button"
              onClick={addPhone}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[var(--ids-accent)] text-white font-medium hover:opacity-90 transition-opacity"
            >
              <Plus className="w-4 h-4" />
              Add
            </button>
          </div>
          {phoneError && (
            <p className="text-sm text-[var(--ids-danger)]">{phoneError}</p>
          )}
          {phones.length > 0 ? (
            <ul className="space-y-2">
              {phones.map((phone) => (
                <li
                  key={phone}
                  className="flex items-center justify-between py-2 px-3 rounded-lg bg-[var(--ids-bg)] border border-[var(--ids-border)]/50 gap-2"
                >
                  <span className="text-[var(--ids-text)] font-mono flex-1 min-w-0 truncate">{phone}</span>
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      type="button"
                      onClick={() => smsTest.mutate([phone])}
                      disabled={smsTest.isPending}
                      className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
                      title="Send test SMS"
                    >
                      {smsTest.isPending ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Send className="w-3.5 h-3.5" />
                      )}
                      Test
                    </button>
                    <button
                      type="button"
                      onClick={() => removePhone(phone)}
                      className="p-1 rounded text-[var(--ids-text-muted)] hover:text-[var(--ids-danger)] hover:bg-[var(--ids-danger)]/10 transition-colors"
                      aria-label={`Remove ${phone}`}
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-[var(--ids-text-muted)] py-4">
              No phone numbers added. Add recipients to receive critical and high-severity alerts via SMS.
            </p>
          )}
          {smsTest.isError && (
            <p className="text-sm text-[var(--ids-danger)]">
              Test failed: {smsTest.error instanceof Error ? smsTest.error.message : 'Unknown error'}
            </p>
          )}
          {smsTest.isSuccess && (
            <p className="text-sm text-emerald-500">Test SMS sent successfully.</p>
          )}
        </div>
      </div>
    </div>
  );
}
