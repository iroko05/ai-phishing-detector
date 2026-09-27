"""Схемы данных API и промежуточных результатов анализа."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# МОДЕЛИ ВХОДЯЩЕГО ПИСЬМА
# ============================================================
class AttachmentInfo(BaseModel):
    filename: str = ""
    size: int = 0
    content_type: str = ""

    # Заполняется анализатором вложений
    extension: str = ""
    dangerous: bool = False
    double_extension: bool = False
    spoofed_extension: bool = False
    macro_office: bool = False
    password_protected: bool = False
    fake_extension: bool = False
    reasons: List[str] = Field(default_factory=list)

    @field_validator("filename", "content_type", "extension", mode="before")
    @classmethod
    def _to_str(cls, v):
        return "" if v is None else str(v)


class EmailInput(BaseModel):
    """Унифицированный вход анализаторов."""

    sender: str = ""
    sender_display_name: str = ""
    recipient: str = ""
    subject: str = ""
    body: str = ""
    html_body: str = ""
    urls: Optional[List[str]] = None
    attachments: List[AttachmentInfo] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    message_id: str = ""
    raw_source: str = ""
    direction: str = "inbound"  # inbound | outbound

    @field_validator("headers", mode="before")
    @classmethod
    def _lower_keys(cls, v):
        if not v:
            return {}
        return {str(k).lower(): str(val) for k, val in v.items()}


class IncomingEmail(EmailInput):
    """Совместимость со старой схемой: поля sender/recipient/subject/body обязательны."""

    sender: str
    recipient: str
    subject: str = ""
    body: str


class MtaEmailInput(BaseModel):
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    body: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    attachments: List[AttachmentInfo] = Field(default_factory=list)

    @field_validator("headers", mode="before")
    @classmethod
    def _lower_keys(cls, v):
        if not v:
            return {}
        return {str(k).lower(): str(val) for k, val in v.items()}


class RawEmailInput(BaseModel):
    """Сырое письмо в формате RFC 5322 (.eml) — разбирается на сервере."""

    raw_email: str
    recipient: str = ""


# ============================================================
# МОДЕЛИ РЕЗУЛЬТАТОВ
# ============================================================
class Evidence(BaseModel):
    rule_id: str
    title: str
    points: int
    category: str = "generic"
    detail: str = ""
    weight: float = 1.0
    weighted_points: float = 0.0
    source: str = "heuristics"  # heuristics | text | url | auth | attachment | ai | policy

    @field_validator("source", mode="before")
    @classmethod
    def _default_source(cls, v):
        return v or "heuristics"


class ModuleReport(BaseModel):
    score: int = 0
    status: str = "ok"  # ok | degraded | not_configured | skipped
    evidence: List[Evidence] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    comment: str = ""


class UrlVerdict(BaseModel):
    """Упрощённый вердикт по ссылке (старое имя поля для совместимости)."""

    url: str
    suspicious: bool = False
    score: int = 0
    domain: str = ""
    reasons: List[str] = Field(default_factory=list)


class UrlLink(BaseModel):
    """Развёрнутый вердикт по ссылке: структура, домен, редиректы, репутация."""

    url: str
    text: str = ""
    domain: str = ""
    registrar_domain: str = ""
    suspicious: bool = False
    score: int = 0
    reasons: List[str] = Field(default_factory=list)
    ip_host: bool = False
    punycode: bool = False
    homoglyph: bool = False
    brand_impersonation: str = ""
    redirects: List[str] = Field(default_factory=list)
    redirect_hops: int = 0
    redirect_status: str = ""
    domain_age_days: Optional[int] = None
    domain_age_status: str = "unknown"
    dns_status: str = "unknown"


class DomainInfo(BaseModel):
    """Репутация домена, встречающегося в письме."""

    domain: str
    score: int = 0
    suspicious: bool = False
    reasons: List[str] = Field(default_factory=list)
    domain_age_days: Optional[int] = None
    domain_age_status: str = "unknown"
    dns_status: str = "unknown"
    brand_impersonation: str = ""
    seen_in_urls: int = 1


class PhishingSignal(BaseModel):
    """Правило, которое сработало в одном из анализаторов."""

    rule_id: str
    title: str
    points: int
    weighted_points: float = 0.0
    category: str = "generic"
    source: str = "heuristics"  # heuristics | text | url | auth | attachment | ai | policy
    detail: str = ""


class AuthReport(BaseModel):
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"
    spf_domain: str = ""
    dkim_domain: str = ""
    dmarc_domain: str = ""
    score: int = 0
    reasons: List[str] = Field(default_factory=list)
    arc: str = ""
    mta_tls: str = ""
    source_ip: str = ""
    authresults: str = ""


class AnalysisResult(BaseModel):
    id: Optional[int] = None
    action: str
    risk_score: int
    risk_level: str
    decision_reason: str
    confidence: int = 0
    analyzed_at: datetime = Field(default_factory=utcnow)
    message_id: str = ""

    # Данные письма — нужны журналу, статистике и карточке на дашборде
    sender: str = ""
    sender_domain: str = ""
    recipient: str = ""
    subject: str = ""

    heuristics_report: ModuleReport
    url_analysis: ModuleReport
    auth_report: ModuleReport
    ai_report: ModuleReport

    # Дополнительные анализаторы движка 2.0
    text_report: ModuleReport = Field(default_factory=ModuleReport)
    attachment_report: ModuleReport = Field(default_factory=ModuleReport)

    # Плоские представления для дашборда
    signals: List[PhishingSignal] = Field(default_factory=list)
    links: List[UrlLink] = Field(default_factory=list)
    domains: List[DomainInfo] = Field(default_factory=list)
    attachments: List[AttachmentInfo] = Field(default_factory=list)
    auth: AuthReport = Field(default_factory=AuthReport)

    # Совместимость со старой схемой ответа
    url_details: List[UrlVerdict] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    weights: Dict[str, float] = Field(default_factory=dict)
    allowlisted: bool = False

    # Классификация и объяснение решения
    phishing_type: str = "unknown"
    targeted: bool = False
    direction: str = "inbound"
    summary: str = ""
    suggested_actions: List[str] = Field(default_factory=list)
    modules_status: Dict[str, str] = Field(default_factory=dict)
    aggregation: Dict[str, Any] = Field(default_factory=dict)
    hard_rules: List[str] = Field(default_factory=list)
    latency_ms: int = 0
    engine_version: str = "2.0.0"


class GatewayResponse(AnalysisResult):
    """Ответ старой схемы для совместимости с существующими клиентами."""

    @property
    def legacy(self) -> dict:
        return {
            "action": self.action,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "decision_reason": self.decision_reason,
            "heuristics_report": self.heuristics_report.model_dump(),
            "ai_report": self.ai_report.model_dump(),
            "url_analysis": self.url_analysis.model_dump(),
        }


class MtaResponse(BaseModel):
    action: str  # accept | tag | reject | quarantine
    risk_score: int
    message: str
    add_headers: Dict[str, str] = Field(default_factory=dict)
    subject_prefix: str = ""
    heuristics_report: ModuleReport
    url_analysis: ModuleReport
    auth_report: ModuleReport
    ai_report: ModuleReport
    text_report: ModuleReport = Field(default_factory=ModuleReport)
    attachment_report: ModuleReport = Field(default_factory=ModuleReport)
    phishing_type: str = "unknown"
    targeted: bool = False
    signals: List[PhishingSignal] = Field(default_factory=list)


class QuarantineItem(BaseModel):
    id: int
    created_at: str
    sender: str
    recipient: str
    subject: str
    risk_score: int
    action: str
    reason: str
    released: bool = False
    released_at: Optional[str] = None
    risk_level: str = ""
    message_id: str = ""
    phishing_type: str = ""


class AllowlistEntry(BaseModel):
    pattern: str
    note: str = ""
    created_at: str = ""


class StatsOverview(BaseModel):
    total: int = 0
    blocked: int = 0
    tagged: int = 0
    delivered: int = 0
    quarantined: int = 0
    released: int = 0
    avg_score: float = 0.0
    ai_available_share: float = 0.0
    top_rules: List[Dict[str, Any]] = Field(default_factory=list)
    top_senders: List[Dict[str, Any]] = Field(default_factory=list)
    hourly: List[Dict[str, Any]] = Field(default_factory=list)
    mta_last_seen: Optional[str] = None
    # Расширение статистики движком 2.0
    levels: Dict[str, int] = Field(default_factory=dict)
    ai_modes: Dict[str, int] = Field(default_factory=dict)
    top_domains: List[Dict[str, Any]] = Field(default_factory=list)
    top_urls: List[Dict[str, Any]] = Field(default_factory=list)
    top_subjects: List[Dict[str, Any]] = Field(default_factory=list)


class RuleInfo(BaseModel):
    """Описание правила — для страницы «Как формируется оценка»."""

    rule_id: str
    title: str
    points: int
    category: str = "generic"
    source: str = "heuristics"
    description: str = ""


class RulesCatalog(BaseModel):
    rules: List[RuleInfo] = Field(default_factory=list)
    weights: Dict[str, float] = Field(default_factory=dict)
    categories: List[Dict[str, Any]] = Field(default_factory=list)
    thresholds: Dict[str, int] = Field(default_factory=dict)
    total: int = 0


class HeadersInput(BaseModel):
    """Разбор «сырых» заголовков без тела письма."""

    raw_headers: str


class AnalyzeOptions(BaseModel):
    """Опции разового анализа (по умолчанию включены все проверки)."""

    use_ai: bool = True
    check_urls: bool = True
    check_redirects: bool = True
    check_reputation: bool = True
    outbound: bool = False
