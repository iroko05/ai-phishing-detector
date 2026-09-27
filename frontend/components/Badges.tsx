'use client';

import { ACTION_COLORS, ACTION_LABELS, scoreColor } from '@/lib/types';

export function ActionBadge({ action }: { action: string }) {
  const color = ACTION_COLORS[action] ?? 'bg-slate-900 text-slate-300 border-slate-700';
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-semibold ${color}`}>
      {ACTION_LABELS[action] ?? action}
    </span>
  );
}

export function ScoreBadge({ score }: { score: number }) {
  return (
    <span className={`font-mono font-bold ${scoreColor(score)}`}>{score}</span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    ok: 'text-emerald-400',
    skipped: 'text-slate-500',
    not_configured: 'text-slate-500',
    degraded: 'text-amber-400',
    pending: 'text-amber-400',
    released: 'text-emerald-400',
    rejected: 'text-red-400',
  };
  const labels: Record<string, string> = {
    ok: 'работает',
    skipped: 'пропущен',
    not_configured: 'не настроен',
    degraded: 'деградация',
    pending: 'ожидает',
    released: 'выпущено',
    rejected: 'отклонено',
  };
  return (
    <span className={`text-xs ${map[status] ?? 'text-slate-400'}`}>
      {labels[status] ?? status}
    </span>
  );
}

export function ModuleCard({
  name,
  title,
  score,
  status,
  comment,
}: {
  name: string;
  title: string;
  score: number;
  status: string;
  comment: string;
}) {
  return (
    <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-xs uppercase tracking-wide text-slate-500">{title}</span>
        <StatusPill status={status} />
      </div>
      <div className="mt-1 flex items-baseline gap-2">
        <span className={`text-xl font-bold font-mono ${scoreColor(score)}`}>{score}</span>
        <span className="text-[11px] text-slate-500">/ 100 · {name}</span>
      </div>
      {comment ? <p className="mt-1 text-xs text-slate-400 line-clamp-2">{comment}</p> : null}
    </div>
  );
}
