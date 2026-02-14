import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { startAttack, getReceivedPackets, ATTACK_TYPES, type AttackType } from '../api/attackerApi';
import { FlaskConical, Play, CheckCircle, XCircle, Loader2, Inbox } from 'lucide-react';
import { format } from 'date-fns';

export function Testing() {
  const [selectedType, setSelectedType] = useState<AttackType | null>(null);
  const [lastResult, setLastResult] = useState<{ success: boolean; message?: string } | null>(null);

  const mutation = useMutation({
    mutationFn: (attackType: AttackType) => startAttack(attackType),
    onSuccess: (data) => {
      setLastResult({
        success: data.success,
        message: data.message ?? (data.success ? 'Attack started successfully' : 'Request completed'),
      });
    },
    onError: (err) => {
      setLastResult({
        success: false,
        message: err instanceof Error ? err.message : 'Unknown error',
      });
    },
  });

  const { data: packets = [], refetch: refetchPackets } = useQuery({
    queryKey: ['receivedPackets'],
    queryFn: getReceivedPackets,
    refetchInterval: 2000,
    retry: false,
  });

  const handleStartAttack = (attackType: AttackType) => {
    setSelectedType(attackType);
    setLastResult(null);
    mutation.mutate(attackType);
    refetchPackets();
  };

  return (
    <div className="space-y-8">
      <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] p-6 shadow-sm">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 rounded-lg bg-amber-500/20">
            <FlaskConical className="w-6 h-6 text-amber-500" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-[var(--ids-text)]">Attack Testing</h3>
            <p className="text-sm text-[var(--ids-text-muted)]">
              Signal the attacker VM to start a specific attack type for IDS validation
            </p>
          </div>
        </div>

        <div className="space-y-4">
          <span className="text-sm font-medium text-[var(--ids-text-muted)]">Attack Type</span>
          <div className="flex flex-wrap gap-2">
            {ATTACK_TYPES.map((type) => (
              <button
                key={type}
                type="button"
                onClick={() => handleStartAttack(type)}
                disabled={mutation.isPending}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all disabled:opacity-60 disabled:cursor-not-allowed ${
                  selectedType === type
                    ? 'bg-[var(--ids-accent)]/20 text-[var(--ids-accent)] border border-[var(--ids-accent)]/50'
                    : 'bg-[var(--ids-border)]/30 text-[var(--ids-text-muted)] border border-transparent hover:bg-[var(--ids-border)]/50 hover:text-[var(--ids-text)]'
                }`}
              >
                {mutation.isPending && selectedType === type ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                {type}
              </button>
            ))}
          </div>
        </div>

        {lastResult && (
          <div
            className={`mt-6 flex items-center gap-2 p-4 rounded-lg ${
              lastResult.success
                ? 'bg-emerald-500/10 border border-emerald-500/30'
                : 'bg-[var(--ids-danger)]/10 border border-[var(--ids-danger)]/30'
            }`}
          >
            {lastResult.success ? (
              <CheckCircle className="w-5 h-5 text-emerald-500 flex-shrink-0" />
            ) : (
              <XCircle className="w-5 h-5 text-[var(--ids-danger)] flex-shrink-0" />
            )}
            <span
              className={
                lastResult.success ? 'text-emerald-400' : 'text-[var(--ids-danger)]'
              }
            >
              {lastResult.success ? 'Success' : 'Error'}: {lastResult.message}
            </span>
          </div>
        )}
      </div>

      <div className="rounded-xl bg-[var(--ids-surface)] border border-[var(--ids-border)] overflow-hidden shadow-sm">
        <h3 className="px-6 py-4 text-lg font-semibold border-b border-[var(--ids-border)] flex items-center gap-2">
          <Inbox className="w-5 h-5 text-[var(--ids-accent)]" />
          Packets Received
        </h3>
        {packets.length > 0 ? (
          <div className="overflow-x-auto max-h-80 overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-[var(--ids-surface)]">
                <tr className="border-b border-[var(--ids-border)]">
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Time
                  </th>
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Source
                  </th>
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Dest
                  </th>
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Protocol
                  </th>
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Port
                  </th>
                  <th className="text-right px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Size
                  </th>
                  <th className="text-left px-6 py-3 text-[var(--ids-text-muted)] font-medium">
                    Type
                  </th>
                </tr>
              </thead>
              <tbody>
                {packets.map((p) => (
                  <tr
                    key={p.id}
                    className="border-b border-[var(--ids-border)]/50 hover:bg-[var(--ids-border)]/30"
                  >
                    <td className="px-6 py-3 text-[var(--ids-text-muted)] font-mono text-xs">
                      {format(new Date(p.timestamp), 'HH:mm:ss.SSS')}
                    </td>
                    <td className="px-6 py-3 font-mono text-[var(--ids-text)] text-xs">
                      {p.sourceIp}
                    </td>
                    <td className="px-6 py-3 font-mono text-[var(--ids-text)] text-xs">
                      {p.destIp}
                    </td>
                    <td className="px-6 py-3 text-[var(--ids-text)]">{p.protocol}</td>
                    <td className="px-6 py-3 text-[var(--ids-text)]">{p.port}</td>
                    <td className="px-6 py-3 text-right text-[var(--ids-text)]">
                      {p.size} B
                    </td>
                    <td className="px-6 py-3">
                      {p.attackType ? (
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-[var(--ids-danger)]/20 text-[var(--ids-danger)]">
                          {p.attackType}
                        </span>
                      ) : (
                        <span className="text-[var(--ids-text-muted)]">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-16 text-[var(--ids-text-muted)]">
            <Inbox className="w-12 h-12 mb-3 opacity-40" />
            <p className="text-sm">No packets received yet</p>
            <p className="text-xs mt-1">Packets will appear here when an attack is active</p>
          </div>
        )}
      </div>
    </div>
  );
}
