'use client';

import { useCallback, useEffect, useState } from 'react';
import { ActionBadge, ScoreBadge, StatusPill } from '@/components/Badges';
import VerdictCard from '@/components/VerdictCard';
import type { AnalysisLogRow, AnalysisResult, HealthPayload, StatsPayload } from '@/lib/types';

interface EmailForm {
  sender: string;
  recipient: string;
  subject: string;
  body: string;
}

const PHISHING_SAMPLE: EmailForm = {
  sender: 'security-update@microsoft-support-portal.ru',
  recipient: 'employee@corp.ru',
  subject: 'Срочно: требуется обновление учётной записи',
  body: 'Уважаемый сотрудник! Руководство службы безопасности требует немедленно '
    + 'перейти по ссылке https://microsoft-secure-login.ru/auth и подтвердить ваш '
    + 'пароль до конца дня во избежание блокировки аккаунта.',
};

export default function DashboardPage() {
  const [stats, setStats] = useState<StatsPayload | null>(null);
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [logs, setLogs] = useState<AnalysisLogRow[]>([]);
  const [error, setError] = useState('');

  const loadDashboard = useCallback(async () => {
    setError('');
    try {
      const [statsRes, logsRes, healthRes] = await Promise.all([
        fetch('/api/stats?days=7', { cache: 'no-store' }),
        fetch('/api/logs?limit=15', { cache: 'no-store' }),
        fetch('/api/health', { cache: 'no-store' }),
      ]);
      if (statsRes.ok) setStats(await statsRes.json());
      if (logsRes.ok) setLogs(await logsRes.json());
      if (healthRes.ok) setHealth(await healthRes.json());
      if (!statsRes.ok && !logsRes.ok) {
        setError('Бэкенд шлюза недоступен — запустите backend (uvicorn main:app)');
      }
    } catch {
      setError('Не удалось связаться с прокси API');
    }
  }, []);

  useEffect(() => {
    loadDashboard();
    const timer = setInterval(loadDashboard, 15_000);
    return () => clearInterval(timer);
  }, [loadDashboard]);

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
      {error && (
        <div className="border border-red-800 bg-red-950/40 text-red-300 rounded-lg px-4 py-3 text-sm">
          {error}
        </div>
      )}

      <StatsPanel stats={stats} health={health} />

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-8">
        <section className="xl:col-span-3 space-y-4">
          <h2 className="text-lg font-semibold text-slate-200">Последние разборы</h2>
          <LogsTable rows={logs} />
        </section>
        <section className="xl:col-span-2">
          <h2 className="text-lg font-semibold text-slate-200 mb-4">Проверка письма</h2>
          <AnalyzerForm onDone={loadDashboard} />
        </section>
      </div>
    </div>
  );
}

function StatsPanel({ stats, health }: { stats: StatsPayload | null; health: HealthPayload | null }) {
  const overview = stats?.overview;
  const cards = [
    { label: 'Всего писем', value: overview?.total ?? '—' },
    { label: 'Заблокировано', value: overview?.blocked ?? '—', accent: 'text-red-400' },
    { label: 'В карантине', value: overview?.quarantine_pending ?? '—', accent: 'text-orange-400' },
    { label: 'Средний риск', value: overview ? `${overview.avg_score}` : '—' },
    { label: 'Доля с ИИ', value: overview ? `${Math.round(overview.ai_share * 100)}%` : '—' },
  ];

  const topRules = (stats?.top_rules ?? []).slice(0, 6);
  const topSenders = (stats?.top_senders ?? []).slice(0, 6);

  return (
    <section className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {cards.map((card) => (
          <div key={card.label} className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div className="text-xs text-slate-500">{card.label}</div>
            <div className={`text-2xl font-bold mt-1 ${card.accent ?? 'text-cyan-400'}`}>
              {card.value}
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs uppercase text-slate-500 mb-2">Состояние шлюза</div>
          <div className="text-sm space-y-1">
            <div>Версия: <span className="font-mono text-slate-300">{health?.version ?? '—'}</span></div>
            <div>БД: <StatusPill status={health?.database === 'ok' ? 'ok' : 'degraded'} /></div>
            <div>ИИ GigaChat: <StatusPill status={health?.ai_configured ? 'ok' : 'not_configured'} /></div>
            <div>MTA-режим: <span className="text-slate-300">{health?.mta?.mode ?? '—'}</span></div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs uppercase text-slate-500 mb-2">Частые правила</div>
          {topRules.length ? (
            <ul className="text-sm space-y-1">
              {topRules.map((rule) => (
                <li key={rule.rule_id} className="flex justify-between gap-2">
                  <span className="text-slate-300 truncate">{rule.rule_id}</span>
                  <span className="font-mono text-slate-500">{rule.hits}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-600">Нет данных за период</p>
          )}
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs uppercase text-slate-500 mb-2">Источники риска</div>
          {topSenders.length ? (
            <ul className="text-sm space-y-1">
              {topSenders.map((sender) => (
                <li key={sender.sender_domain} className="flex justify-between gap-2">
                  <span className="text-slate-300 truncate">{sender.sender_domain}</span>
                  <span className="font-mono text-red-400">{sender.positives}/{sender.n}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-600">Нет данных за период</p>
          )}
        </div>
      </div>
    </section>
  );
}

function LogsTable({ rows }: { rows: AnalysisLogRow[] }) {
  if (!rows.length) {
    return (
      <div className="border border-dashed border-slate-800 rounded-xl h-40 flex items-center justify-center text-sm text-slate-600">
        Разборов пока нет — проверьте письмо в форме справа
      </div>
    );
  }
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
            <th className="px-4 py-2">Время</th>
            <th className="px-4 py-2">Отправитель</th>
            <th className="px-4 py-2">Тема</th>
            <th className="px-4 py-2 text-right">Риск</th>
            <th className="px-4 py-2">Решение</th>
            <th className="px-4 py-2">Тип</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="border-b border-slate-800/60 hover:bg-slate-950/60">
              <td className="px-4 py-2 text-xs text-slate-500 whitespace-nowrap">
                {new Date(row.created_at).toLocaleString('ru-RU')}
              </td>
              <td className="px-4 py-2 text-slate-300 max-w-[180px] truncate" title={row.sender}>
                {row.sender || '—'}
              </td>
              <td className="px-4 py-2 text-slate-300 max-w-[220px] truncate" title={row.subject}>
                {row.subject || '(без темы)'}
              </td>
              <td className="px-4 py-2 text-right"><ScoreBadge score={row.score} /></td>
              <td className="px-4 py-2"><ActionBadge action={row.action} /></td>
              <td className="px-4 py-2 text-xs text-slate-500">{row.phishing_type || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AnalyzerForm({ onDone }: { onDone: () => void }) {
  const [form, setForm] = useState<EmailForm>(PHISHING_SAMPLE);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const response = await fetch('/api/gateway/intercept', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const payload = await response.json();
      if (!response.ok) {
        setError(payload.detail ?? `Ошибка ${response.status}`);
        setResult(null);
      } else {
        setResult(payload as AnalysisResult);
        onDone();
      }
    } catch {
      setError('Сеть недоступна');
    } finally {
      setLoading(false);
    }
  };

  const field = (label: string, key: keyof EmailForm, textarea = false) => (
    <div>
      <label className="block text-xs uppercase text-slate-500 mb-1">{label}</label>
      {textarea ? (
        <textarea
          rows={5}
          value={form[key]}
          onChange={(e) => setForm({ ...form, [key]: e.target.value })}
          className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
        />
      ) : (
        <input
          type="text"
          value={form[key]}
          onChange={(e) => setForm({ ...form, [key]: e.target.value })}
          className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
        />
      )}
    </div>
  );

  return (
    <div className="space-y-4">
      <form onSubmit={submit} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        {field('Отправитель', 'sender')}
        {field('Получатель', 'recipient')}
        {field('Тема', 'subject')}
        {field('Текст письма', 'body', true)}
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold py-2.5 rounded transition-colors disabled:opacity-50"
        >
          {loading ? 'Анализ шлюзом…' : 'Перехватить и проверить'}
        </button>
      </form>

      {error && <div className="text-sm text-red-400 border border-red-900 rounded p-3 bg-red-950/30">{error}</div>}

      {result && <VerdictCard result={result} />}
    </div>
  );
}
