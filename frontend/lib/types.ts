/** Типы ответов REST API шлюза (зеркало pydantic-схем бэкенда). */

export interface Evidence {
  rule_id: string;
  title: string;
  points: number;
  category: string;
  detail: string;
  weighted_points?: number;
}

export interface ModuleReport {
  score: number;
  status: 'ok' | 'degraded' | 'not_configured' | 'skipped' | string;
  evidence: Evidence[];
  details: Record<string, unknown>;
  comment: string;
}

export interface Signal {
  rule_id: string;
  title: string;
  points: number;
  weighted_points: number;
  category: string;
  source: string;
  detail: string;
}

export interface UrlLink {
  url: string;
  domain: string;
  suspicious: boolean;
  score: number;
  reasons: string[];
}

export interface DomainInfo {
  domain: string;
  score: number;
  suspicious: boolean;
  reasons: string[];
}

export interface AttachmentInfo {
  filename: string;
  size: number;
  content_type: string;
  dangerous: boolean;
  double_extension: boolean;
  macro_office: boolean;
  password_protected: boolean;
  reasons: string[];
}

export interface AuthReport {
  spf: string;
  dkim: string;
  dmarc: string;
  score: number;
  reasons: string[];
}

export interface AnalysisResult {
  id: number | null;
  action: 'allow' | 'warn' | 'hold' | 'quarantine' | 'block' | string;
  risk_score: number;
  risk_level: string;
  decision_reason: string;
  confidence: number;
  sender: string;
  sender_domain: string;
  recipient: string;
  subject: string;
  heuristics_report: ModuleReport;
  url_analysis: ModuleReport;
  auth_report: ModuleReport;
  ai_report: ModuleReport;
  attachment_report: ModuleReport;
  signals: Signal[];
  links: UrlLink[];
  domains: DomainInfo[];
  attachments: AttachmentInfo[];
  auth: AuthReport;
  phishing_type: string;
  summary: string;
  suggested_actions: string[];
  modules_status: Record<string, string>;
  aggregation: Record<string, unknown>;
  allowlisted: boolean;
  latency_ms: number;
}

export interface AnalysisLogRow {
  id: number;
  created_at: string;
  source: string;
  sender: string;
  sender_domain: string;
  recipient: string;
  subject: string;
  score: number;
  level: string;
  action: string;
  reason: string;
  phishing_type: string;
  ai_status: string;
  latency_ms: number;
  summary?: string;
}

export interface StatsOverview {
  total: number;
  avg_score: number;
  blocked: number;
  held: number;
  warned: number;
  delivered: number;
  ai_share: number;
  quarantine_pending: number;
  quarantine_released: number;
}

export interface StatsPayload {
  overview: StatsOverview;
  period_days: number;
  by_action: { action: string; n: number; avg_score: number }[];
  by_type: { phishing_type: string; n: number }[];
  daily: { day: string; total: number; blocked: number; avg_score: number }[];
  hourly: { hour: string; total: number; blocked: number }[];
  top_senders: { sender_domain: string; n: number; positives: number; max_score: number }[];
  top_rules: { rule_id: string; hits: number }[];
  top_urls: { domain: string; hits: number; suspicious: number; max_score: number }[];
  quarantine: { pending: number; released: number; rejected: number; total: number };
  mta_last_seen: string | null;
  ai_stats: Record<string, number>;
}

export interface QuarantineItem {
  id: number;
  created_at: string;
  analysis_id: number | null;
  sender: string;
  recipient: string;
  subject: string;
  score: number;
  action: string;
  reason: string;
  phishing_type: string;
  status: 'pending' | 'released' | 'rejected' | string;
  handled_at: string | null;
  handled_by: string;
  release_note: string;
  raw_size?: number;
}

export interface ListEntry {
  id: number;
  pattern: string;
  kind: 'allow' | 'deny';
  entry_type: string;
  note: string;
  created_at: string;
  expires_at: string | null;
}

export interface HealthPayload {
  status: string;
  version: string;
  ai_configured: boolean;
  mta: { mode: string; processed?: number; blocked?: number };
  database: string;
}

export const ACTION_LABELS: Record<string, string> = {
  allow: 'Доставлено',
  warn: 'Предупреждение',
  hold: 'Задержано',
  quarantine: 'Карантин',
  block: 'Отклонено',
};

export const ACTION_COLORS: Record<string, string> = {
  allow: 'bg-emerald-950/60 text-emerald-300 border-emerald-800',
  warn: 'bg-amber-950/60 text-amber-300 border-amber-800',
  hold: 'bg-orange-950/60 text-orange-300 border-orange-800',
  quarantine: 'bg-red-950/60 text-red-300 border-red-800',
  block: 'bg-red-950/80 text-red-200 border-red-700',
};

export function scoreColor(score: number): string {
  if (score >= 70) return 'text-red-400';
  if (score >= 55) return 'text-orange-400';
  if (score >= 35) return 'text-amber-400';
  return 'text-emerald-400';
}
