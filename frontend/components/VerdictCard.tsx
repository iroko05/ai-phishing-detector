'use client';

import { ActionBadge, ModuleCard, ScoreBadge } from '@/components/Badges';
import type { AnalysisResult } from '@/lib/types';

/** Карточка полного вердикта шлюза: оценка, модули, сигналы, рекомендации. */
export default function VerdictCard({ result }: { result: AnalysisResult }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-xs uppercase text-slate-500">Вердикт шлюза</div>
          <div className="text-2xl font-bold">
            <ScoreBadge score={result.risk_score} />
            <span className="text-slate-500 text-base"> / 100</span>
          </div>
        </div>
        <ActionBadge action={result.action} />
      </div>

      <p className="text-sm text-slate-300">{result.decision_reason}</p>

      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <ModuleCard name="эвристика" title="Содержимое" score={result.heuristics_report.score}
                    status={result.heuristics_report.status} comment={result.heuristics_report.comment} />
        <ModuleCard name="ссылки" title="URL-анализ" score={result.url_analysis.score}
                    status={result.url_analysis.status} comment={result.url_analysis.comment} />
        <ModuleCard name="аутентиф." title="SPF/DKIM/DMARC" score={result.auth_report.score}
                    status={result.auth_report.status} comment={result.auth_report.comment} />
        <ModuleCard name="вложения" title="Вложения" score={result.attachment_report.score}
                    status={result.attachment_report.status} comment={result.attachment_report.comment} />
        <ModuleCard name="ИИ" title="GigaChat" score={result.ai_report.score}
                    status={result.ai_report.status} comment={result.ai_report.comment} />
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
          <div className="text-xs uppercase tracking-wide text-slate-500">Тип атаки</div>
          <div className="mt-1 text-sm font-semibold text-slate-200">{result.phishing_type}</div>
          <div className="mt-1 text-[11px] text-slate-500">
            задержка {result.latency_ms} мс · уверенность {result.confidence}%
          </div>
        </div>
      </div>

      {result.signals.length > 0 && (
        <div>
          <div className="text-xs uppercase text-slate-500 mb-2">Сработавшие сигналы</div>
          <ul className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
            {result.signals.slice(0, 12).map((signal, index) => (
              <li key={`${signal.rule_id}-${index}`} className="text-xs bg-slate-950 border border-slate-800 rounded px-3 py-1.5">
                <span className="text-slate-300">{signal.title}</span>
                {signal.points > 0 && <span className="text-red-400 font-mono"> +{signal.points}</span>}
                {signal.points < 0 && <span className="text-emerald-400 font-mono"> {signal.points}</span>}
                {signal.detail && <div className="text-slate-600 mt-0.5">{signal.detail}</div>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.suggested_actions.length > 0 && (
        <div>
          <div className="text-xs uppercase text-slate-500 mb-1">Рекомендации SOC</div>
          <ul className="text-xs text-slate-400 list-disc list-inside space-y-0.5">
            {result.suggested_actions.map((action) => <li key={action}>{action}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}
