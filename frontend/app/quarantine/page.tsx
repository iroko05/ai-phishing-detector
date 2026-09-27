'use client';

import { useCallback, useEffect, useState } from 'react';
import { ActionBadge, ScoreBadge, StatusPill } from '@/components/Badges';
import type { QuarantineItem } from '@/lib/types';

const STATUSES = [
  { value: 'pending', label: 'Ожидают' },
  { value: 'released', label: 'Выпущены' },
  { value: 'rejected', label: 'Отклонены' },
  { value: 'all', label: 'Все' },
];

export default function QuarantinePage() {
  const [status, setStatus] = useState('pending');
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [stats, setStats] = useState<{ pending: number; released: number; rejected: number } | null>(null);
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState<number | null>(null);

  const load = useCallback(async () => {
    setError('');
    try {
      const response = await fetch(`/api/quarantine?status=${status}&limit=100`, { cache: 'no-store' });
      if (!response.ok) {
        setError('Не удалось получить карантин — проверьте бэкенд');
        return;
      }
      const payload = await response.json();
      setItems(payload.items ?? []);
      setStats(payload.stats ?? null);
    } catch {
      setError('Сеть недоступна');
    }
  }, [status]);

  useEffect(() => {
    load();
  }, [load]);

  const handle = async (id: number, action: 'release' | 'reject') => {
    setBusyId(id);
    try {
      const response = await fetch(`/api/quarantine/${id}/${action}`, { method: 'POST' });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        setError(payload?.detail ?? `Ошибка ${response.status} (нужен X-Admin-Token?)`);
      } else {
        await load();
      }
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold text-slate-200">Карантин писем</h1>
        {stats && (
          <span className="text-xs text-slate-500">
            ожидают {stats.pending} · выпущены {stats.released} · отклонены {stats.rejected}
          </span>
        )}
        <div className="ml-auto flex gap-1">
          {STATUSES.map((option) => (
            <button
              key={option.value}
              onClick={() => setStatus(option.value)}
              className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                status === option.value
                  ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-900'
                  : 'text-slate-400 hover:bg-slate-900 border border-transparent'
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="border border-red-800 bg-red-950/40 text-red-300 rounded-lg px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {items.length === 0 ? (
        <div className="border border-dashed border-slate-800 rounded-xl h-40 flex items-center justify-center text-sm text-slate-600">
          Записей нет — карантин пуст
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
                <th className="px-4 py-2">Время</th>
                <th className="px-4 py-2">Отправитель</th>
                <th className="px-4 py-2">Тема</th>
                <th className="px-4 py-2 text-right">Риск</th>
                <th className="px-4 py-2">Тип</th>
                <th className="px-4 py-2">Статус</th>
                <th className="px-4 py-2 text-right">Действия</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} className="border-b border-slate-800/60 hover:bg-slate-950/60 align-top">
                  <td className="px-4 py-2 text-xs text-slate-500 whitespace-nowrap">
                    {new Date(item.created_at).toLocaleString('ru-RU')}
                  </td>
                  <td className="px-4 py-2 text-slate-300 max-w-[180px] truncate" title={item.sender}>
                    {item.sender || '—'}
                  </td>
                  <td className="px-4 py-2 max-w-[260px]">
                    <div className="text-slate-300 truncate" title={item.subject}>{item.subject || '(без темы)'}</div>
                    <div className="text-xs text-slate-600 truncate" title={item.reason}>{item.reason}</div>
                  </td>
                  <td className="px-4 py-2 text-right"><ScoreBadge score={item.score} /></td>
                  <td className="px-4 py-2 text-xs text-slate-500">{item.phishing_type || '—'}</td>
                  <td className="px-4 py-2"><StatusPill status={item.status} /></td>
                  <td className="px-4 py-2 text-right whitespace-nowrap">
                    {item.status === 'pending' ? (
                      <div className="flex gap-2 justify-end">
                        <button
                          disabled={busyId === item.id}
                          onClick={() => handle(item.id, 'release')}
                          className="px-2.5 py-1 rounded border border-emerald-800 text-emerald-300 text-xs hover:bg-emerald-950/60 disabled:opacity-50"
                        >
                          Выпустить
                        </button>
                        <button
                          disabled={busyId === item.id}
                          onClick={() => handle(item.id, 'reject')}
                          className="px-2.5 py-1 rounded border border-red-800 text-red-300 text-xs hover:bg-red-950/60 disabled:opacity-50"
                        >
                          Отклонить
                        </button>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-600">
                        {item.handled_at ? new Date(item.handled_at).toLocaleString('ru-RU') : ''}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="text-xs text-slate-600">
        Выпуск и отклонение — административные действия: прокси добавляет X-Admin-Token из переменной
        GATEWAY_ADMIN_TOKEN и пишет событие в журнал аудита шлюза.
      </p>
    </div>
  );
}
