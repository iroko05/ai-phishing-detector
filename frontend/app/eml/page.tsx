'use client';

import { useState } from 'react';
import { ScoreBadge } from '@/components/Badges';
import VerdictCard from '@/components/VerdictCard';
import type { AnalysisResult } from '@/lib/types';

export default function EmlPage() {
  const [rawEmail, setRawEmail] = useState('');
  const [fileName, setFileName] = useState('');
  const [recipient, setRecipient] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const onFile = async (file: File | null) => {
    if (!file) return;
    if (file.size > 2_000_000) {
      setError('Файл больше 2 МБ — шлюз не примет такое письмо');
      return;
    }
    setFileName(file.name);
    setError('');
    setRawEmail(await file.text());
  };

  const analyze = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!rawEmail.trim()) {
      setError('Вставьте текст письма или выберите .eml-файл');
      return;
    }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const response = await fetch('/api/gateway/analyze-raw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: rawEmail, recipient: recipient.trim() }),
      });
      const payload = await response.json();
      if (!response.ok) {
        setError(payload.detail ?? `Ошибка ${response.status}`);
      } else {
        setResult(payload as AnalysisResult);
      }
    } catch {
      setError('Сеть недоступна');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-8 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-200">Разбор сырого письма (.eml)</h1>
        <p className="text-sm text-slate-500 mt-1">
          Письмо разбирается на сервере: заголовки (включая SPF/DKIM/DMARC), MIME-части,
          вложения и ссылки — затем проходит полный конвейер шлюза.
        </p>
      </div>

      <form onSubmit={analyze} className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div>
            <label className="block text-xs uppercase text-slate-500 mb-2">
              Файл .eml (RFC 5322)
            </label>
            <label className="flex flex-col items-center justify-center h-28 border border-dashed border-slate-700 rounded-lg cursor-pointer hover:border-cyan-600 text-sm text-slate-500">
              <input
                type="file"
                accept=".eml,.txt,.msg,message/rfc822,text/plain"
                className="hidden"
                onChange={(e) => onFile(e.target.files?.[0] ?? null)}
              />
              {fileName
                ? <span className="text-cyan-300">{fileName}</span>
                : <span>Перетащите или выберите файл письма</span>}
            </label>
          </div>

          <div>
            <label className="block text-xs uppercase text-slate-500 mb-1">
              Получатель (необязательно, если нет заголовка To)
            </label>
            <input
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              placeholder="employee@corp.ru"
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs uppercase text-slate-500 mb-1">
              Или вставьте исходник письма
            </label>
            <textarea
              rows={12}
              value={rawEmail}
              onChange={(e) => { setRawEmail(e.target.value); setFileName(''); }}
              placeholder={'From: security@sberbank-secure.top\nSubject: Срочно подтвердите пароль\n…'}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !rawEmail.trim()}
            className="w-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold py-2.5 rounded transition-colors disabled:opacity-50"
          >
            {loading ? 'Разбор конвейером…' : 'Проанализировать письмо'}
          </button>
        </div>

        <div className="space-y-4">
          {error && (
            <div className="border border-red-800 bg-red-950/40 text-red-300 rounded-lg px-4 py-3 text-sm">
              {error}
            </div>
          )}
          {result ? (
            <>
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-sm space-y-1">
                <div className="text-xs uppercase text-slate-500 mb-1">Разобранное письмо</div>
                <div>Отправитель: <span className="text-slate-300">{result.sender || '—'}</span></div>
                <div>Получатель: <span className="text-slate-300">{result.recipient || '—'}</span></div>
                <div>Тема: <span className="text-slate-300">{result.subject || '(без темы)'}</span></div>
                <div className="pt-1">
                  SPF <span className="text-slate-300">{result.auth.spf}</span> ·
                  DKIM <span className="text-slate-300">{result.auth.dkim}</span> ·
                  DMARC <span className="text-slate-300">{result.auth.dmarc}</span>
                </div>
              </div>
              <VerdictCard result={result} />
              <LinksPanel result={result} />
              <AttachmentsPanel result={result} />
            </>
          ) : (
            <div className="border border-dashed border-slate-800 rounded-xl h-64 flex items-center justify-center text-sm text-slate-600">
              Результат разбора появится здесь
            </div>
          )}
        </div>
      </form>
    </div>
  );
}

function LinksPanel({ result }: { result: AnalysisResult }) {
  if (!result.links.length) return null;
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="text-xs uppercase text-slate-500 mb-2">Ссылки ({result.links.length})</div>
      <ul className="space-y-2 max-h-60 overflow-y-auto pr-1">
        {result.links.map((link, index) => (
          <li key={index} className="text-xs bg-slate-950 border border-slate-800 rounded px-3 py-2">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-slate-300 truncate">{link.url}</span>
              <ScoreBadge score={link.score} />
            </div>
            {link.reasons.length > 0 && (
              <ul className="mt-1 list-disc list-inside text-slate-600 space-y-0.5">
                {link.reasons.slice(0, 3).map((reason, i) => <li key={i}>{reason}</li>)}
              </ul>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function AttachmentsPanel({ result }: { result: AnalysisResult }) {
  if (!result.attachments.length) return null;
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="text-xs uppercase text-slate-500 mb-2">Вложения ({result.attachments.length})</div>
      <ul className="space-y-2">
        {result.attachments.map((attachment, index) => (
          <li key={index} className="text-xs bg-slate-950 border border-slate-800 rounded px-3 py-2">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-slate-300 truncate">{attachment.filename}</span>
              <span className="text-slate-500">{(attachment.size / 1024).toFixed(1)} КБ</span>
            </div>
            {attachment.reasons.length > 0 && (
              <ul className="mt-1 list-disc list-inside text-red-400/80 space-y-0.5">
                {attachment.reasons.slice(0, 3).map((reason, i) => <li key={i}>{reason}</li>)}
              </ul>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
