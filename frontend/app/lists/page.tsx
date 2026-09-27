'use client';

import { useCallback, useEffect, useState } from 'react';
import type { ListEntry } from '@/lib/types';

export default function ListsPage() {
  const [kind, setKind] = useState<'allow' | 'deny'>('allow');
  const [entries, setEntries] = useState<ListEntry[]>([]);
  const [pattern, setPattern] = useState('');
  const [note, setNote] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError('');
    try {
      const response = await fetch(`/api/lists?kind=${kind}`, { cache: 'no-store' });
      if (!response.ok) {
        setError('Не удалось загрузить списки — проверьте бэкенд');
        return;
      }
      setEntries(await response.json());
    } catch {
      setError('Сеть недоступна');
    }
  }, [kind]);

  useEffect(() => {
    load();
  }, [load]);

  const add = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!pattern.trim()) return;
    setBusy(true);
    setError('');
    try {
      const query = new URLSearchParams({ pattern: pattern.trim(), kind, note: note.trim() });
      const response = await fetch(`/api/lists?${query}`, { method: 'POST' });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        setError(payload?.detail ?? `Ошибка ${response.status} (нужен X-Admin-Token?)`);
      } else {
        setPattern('');
        setNote('');
        await load();
      }
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: number) => {
    setBusy(true);
    try {
      const response = await fetch(`/api/lists/${id}`, { method: 'DELETE' });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        setError(payload?.detail ?? `Ошибка ${response.status}`);
      } else {
        await load();
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold text-slate-200">Списки отправителей</h1>
        <div className="ml-auto flex gap-1">
          {(['allow', 'deny'] as const).map((value) => (
            <button
              key={value}
              onClick={() => setKind(value)}
              className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                kind === value
                  ? value === 'allow'
                    ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-900'
                    : 'bg-red-950/60 text-red-300 border border-red-900'
                  : 'text-slate-400 hover:bg-slate-900 border border-transparent'
              }`}
            >
              {value === 'allow' ? 'Белый список' : 'Чёрный список'}
            </button>
          ))}
        </div>
      </div>

      <p className="text-sm text-slate-500">
        {kind === 'allow'
          ? 'Письма из белого списка доставляются без ограничений (проверки всё равно выполняются для статистики).'
          : 'Письма из чёрного списка отклоняются сразу, сетевые проверки не расходуются.'}
        {' '}Поддерживаются домены (example.ru, включая поддомены), точные адреса (user@example.ru)
        и регулярные выражения с префиксом <code className="text-cyan-400">re:</code>.
      </p>

      <form onSubmit={add} className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-wrap gap-3 items-end">
        <div className="flex-1 min-w-[220px]">
          <label className="block text-xs uppercase text-slate-500 mb-1">Шаблон</label>
          <input
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            placeholder={kind === 'allow' ? 'partner.ru' : 're:выигрыш.*приз'}
            className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="flex-1 min-w-[180px]">
          <label className="block text-xs uppercase text-slate-500 mb-1">Примечание</label>
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="кем и почему добавлено"
            className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <button
          type="submit"
          disabled={busy || !pattern.trim()}
          className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold px-5 py-2 rounded text-sm disabled:opacity-50"
        >
          Добавить
        </button>
      </form>

      {error && (
        <div className="border border-red-800 bg-red-950/40 text-red-300 rounded-lg px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {entries.length === 0 ? (
        <div className="border border-dashed border-slate-800 rounded-xl h-32 flex items-center justify-center text-sm text-slate-600">
          Список пуст
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
                <th className="px-4 py-2">Шаблон</th>
                <th className="px-4 py-2">Тип</th>
                <th className="px-4 py-2">Примечание</th>
                <th className="px-4 py-2">Добавлено</th>
                <th className="px-4 py-2 text-right"></th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id} className="border-b border-slate-800/60 hover:bg-slate-950/60">
                  <td className="px-4 py-2 font-mono text-slate-300">{entry.pattern}</td>
                  <td className="px-4 py-2 text-xs text-slate-500">{entry.entry_type}</td>
                  <td className="px-4 py-2 text-slate-400 max-w-[240px] truncate" title={entry.note}>
                    {entry.note || '—'}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-500 whitespace-nowrap">
                    {entry.created_at ? new Date(entry.created_at).toLocaleString('ru-RU') : '—'}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <button
                      disabled={busy}
                      onClick={() => remove(entry.id)}
                      className="px-2.5 py-1 rounded border border-slate-700 text-slate-400 text-xs hover:bg-slate-800 disabled:opacity-50"
                    >
                      Удалить
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
