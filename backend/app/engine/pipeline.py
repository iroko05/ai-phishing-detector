"""
Конвейер анализа письма: контекст → независимые модули → скоринг → вердикт.

Порядок важен:
  1. белый/чёрный список — известные источники снимаются с проверки до сетевых вызовов;
  2. заголовки аутентификации — самый дешёвый и самый надёжный сигнал;
  3. эвристики содержимого, вложения и ссылки — независимые модули;
  4. GigaChat — самый дорогой шаг, вызывается выборочно (дорогая квота, задержка);
  5. движок взвешенно агрегирует доступные модули и объясняет решение.

Конвейер не роняет запрос из-за отказа отдельного модуля: отказ = «модуль
недоступен», его вес перераспределяется, статус попадает в modules_status.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from app.analyzers.attachments import scan_attachments
from app.analyzers.email_auth import evaluate_auth
from app.analyzers.email_parser import authentication_context, parse_raw_email
from app.analyzers.gigachat import GigaChatClient, get_ai_client
from app.analyzers.heuristics import MailContext, run_heuristics
from app.analyzers.url_intel import UrlIntel
from app.config import Settings, get_settings
from app.schemas import (
    AnalysisResult,
    AttachmentInfo,
    AuthReport,
    DomainInfo,
    EmailInput,
    Evidence,
    ModuleReport,
    PhishingSignal,
    UrlLink,
    UrlVerdict,
)
from app.storage.stores import PatternStore

from .scoring import ScoringEngine, build_engine

logger = logging.getLogger("gateway.pipeline")

ADDRESS_RE = re.compile(r'^(?:"?([^">]*)"?)\s*<([^>]+)>$')

SPF_POINTS = {"fail": 45, "permerror": 45, "softfail": 22, "none": 10,
              "temperror": 10, "unknown": 10, "neutral": 10, "pass": 0}
DKIM_POINTS = {"fail": 35, "permerror": 35, "none": 12, "temperror": 12,
               "unknown": 12, "policy": 20, "pass": 0}
DMARC_POINTS = {"fail": 45, "permerror": 45, "none": 15, "temperror": 15,
                "unknown": 15, "pass": 0}

BRAND_HINTS = ("сбер", "sber", "альфа", "alfa", "втб", "vtb", "тинькофф", "tinkoff",
               "t-bank", "газпром", "gazprom", "ozon", "wildberries", "яндекс", "yandex",
               "госуслуг", "gosuslug", "microsoft", "apple", "paypal", "binance")

# Провалы аутентификации, которые в одиночку тянут вердикт вверх (ov_auth_broken);
# none/unknown — «не настроено/неизвестно», это мягкий сигнал, не жёсткий.
AUTH_HARD_FAILS = {"fail", "permerror", "softfail"}


def split_address(value: Optional[str]) -> Tuple[str, str]:
    """``"Иван <ivan@corp.ru>"`` → ``("Иван", "ivan@corp.ru")``."""
    raw = (value or "").strip()
    match = ADDRESS_RE.match(raw)
    if match:
        return match.group(1).strip().strip('"'), match.group(2).strip().lower()
    return "", raw.strip("<> ;").lower()


def domain_of(address: str) -> str:
    address = (address or "").strip().lower()
    return address.rsplit("@", 1)[-1] if "@" in address else address


def build_context(*, sender: str = "", display_name: str = "", recipient: str = "",
                  subject: str = "", body: str = "", html_body: str = "",
                  headers: Optional[Dict[str, str]] = None,
                  attachments: Optional[List[Any]] = None,
                  urls: Optional[List[str]] = None) -> MailContext:
    header_map = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    parsed_display, address = split_address(sender or header_map.get("from", ""))
    recipient_display, recipient_address = split_address(
        recipient or header_map.get("to", ""))
    return MailContext(
        sender=address,
        sender_local=address.split("@")[0] if "@" in address else "",
        sender_domain=domain_of(address),
        display_name=display_name or parsed_display,
        recipient=recipient_address,
        recipient_local=recipient_address.split("@")[0] if "@" in recipient_address else "",
        subject=subject or header_map.get("subject", ""),
        body=body,
        html_body=html_body,
        headers=header_map,
        attachments=list(attachments or []),
        urls=list(urls or []),
    )


def context_from_parsed(parsed: Dict[str, Any]) -> MailContext:
    return build_context(
        sender=parsed.get("sender", ""),
        display_name=parsed.get("sender_display", ""),
        recipient=parsed.get("recipient", ""),
        subject=parsed.get("subject", ""),
        body=parsed.get("text", ""),
        html_body=parsed.get("html", ""),
        headers=parsed.get("headers"),
        attachments=parsed.get("attachments"),
        urls=parsed.get("urls"),
    )


class Pipeline:
    """Экземпляр живёт в состоянии приложения: кэши доменов и ИИ переиспользуются."""

    def __init__(self, settings: Optional[Settings] = None,
                 patterns: Optional[PatternStore] = None) -> None:
        self.settings = settings or get_settings()
        # Списки отправителей из БД подключены по умолчанию: белый/чёрный список
        # должен влиять на вердикт без ручной сборки конвейера.
        self.patterns: PatternStore = patterns or PatternStore()
        self.engine: ScoringEngine = build_engine(self.settings, self.patterns)
        self.url_intel = UrlIntel(settings=self.settings)
        self.ai: GigaChatClient = get_ai_client()

    # ============================================================ вход
    async def analyze_email(self, email: EmailInput, *, source: str = "api",
                            use_ai: Optional[bool] = None) -> AnalysisResult:
        started = time.perf_counter()
        ctx = build_context(
            sender=email.sender, display_name=email.sender_display_name,
            recipient=email.recipient, subject=email.subject, body=email.body,
            html_body=email.html_body, headers=email.headers,
            attachments=list(email.attachments), urls=email.urls,
        )
        if not ctx.urls:
            ctx.urls = self._extract_urls(ctx)
        return await self._run(ctx, email.raw_source, source=source,
                               use_ai=use_ai, started=started,
                               direction=email.direction)

    async def analyze_raw(self, raw_email: str, recipient_hint: str = "",
                          *, source: str = "eml",
                          use_ai: Optional[bool] = None) -> AnalysisResult:
        started = time.perf_counter()
        parsed = await asyncio.to_thread(parse_raw_email, raw_email, recipient_hint)
        ctx = context_from_parsed(parsed)
        ctx.headers.setdefault("message-id", parsed.get("message_id", ""))
        email = EmailInput(
            sender=ctx.sender, sender_display_name=ctx.display_name,
            recipient=ctx.recipient, subject=ctx.subject, body=ctx.body,
            html_body=ctx.html_body, urls=ctx.urls,
            attachments=[a for a in parsed.get("attachments", [])
                         if isinstance(a, AttachmentInfo)],
            headers=ctx.headers, message_id=parsed.get("message_id", ""),
            raw_source=raw_email[: self.settings.max_email_size],
        )
        return await self._run(ctx, raw_email, source=source, use_ai=use_ai,
                               started=started, direction=email.direction,
                               auth_context=authentication_context(parsed))

    # ============================================================ ядро
    async def _run(self, ctx: MailContext, raw_source: str, *, source: str,
                   use_ai: Optional[bool], started: float,
                   direction: str = "inbound",
                   auth_context: str = "") -> AnalysisResult:
        settings = self.settings

        allow_hit = self.engine.allowlist_match(ctx.sender_domain, ctx.sender)
        deny_hit = self.engine.denylist_match(ctx)

        # --- модуль 1: аутентификация (без сети) --------------------------
        auth_report = evaluate_auth(ctx.headers, ctx.sender_domain)
        auth_module = self._auth_module(auth_report)

        # --- модуль 2: эвристики содержимого ------------------------------
        heur_score, heur_evidence = run_heuristics(ctx)
        heuristics_module = ModuleReport(
            score=heur_score, status="ok", evidence=heur_evidence,
            comment="Правила содержимого, HTML и конверта письма",
        )

        # --- модуль 3: вложения -------------------------------------------
        attachment_module, attachment_rows = scan_attachments(
            ctx.attachments, ctx.body or ctx.html_body)

        # --- модуль 4: ссылки (сеть → отдельный поток) ---------------------
        if ctx.urls:
            url_module, url_verdicts = await asyncio.to_thread(
                self.url_intel.analyze, ctx.urls[: settings.max_urls_per_email])
        else:
            url_module, url_verdicts = ModuleReport(score=0, status="skipped",
                                                    comment="Ссылок в письме нет"), []

        # --- модуль 5: GigaChat (выборочно) --------------------------------
        ai_wanted = use_ai if use_ai is not None else self._needs_ai(
            ctx, auth_report, heur_score, url_module.score, bool(allow_hit), bool(deny_hit))
        if ai_wanted:
            ai_module = await asyncio.to_thread(
                self.ai.analyze, ctx.subject,
                self._ai_text(ctx, auth_context),
                f"Данные шлюза: SPF={auth_report.spf}, DKIM={auth_report.dkim}, "
                f"DMARC={auth_report.dmarc}, домен отправителя={ctx.sender_domain or 'нет'}",
            )
        else:
            ai_module = ModuleReport(
                score=0, status="skipped",
                comment="ИИ не привлекался: быстрый вердикт однозначен "
                        "(экономия квоты и задержки)",
            )

        modules: Dict[str, ModuleReport] = {
            "heuristics": heuristics_module,
            "urls": url_module,
            "auth": auth_module,
            "attachments": attachment_module,
            "ai": ai_module,
        }

        decision = self.engine.decide(modules, ctx, allow_hit=allow_hit, deny_hit=deny_hit)
        signals = self._signals(modules, decision)
        phishing_type = self._classify(ctx, auth_report, ai_module, signals)

        result = AnalysisResult(
            action=decision["action"],
            risk_score=decision["score"],
            risk_level=decision["level"],
            decision_reason=decision["reason"],
            confidence=int(round(decision["confidence"] * 100)),
            message_id=ctx.headers.get("message-id", ""),
            sender=ctx.sender,
            sender_domain=ctx.sender_domain,
            recipient=ctx.recipient,
            subject=ctx.subject,
            heuristics_report=heuristics_module,
            url_analysis=url_module,
            auth_report=auth_module,
            ai_report=ai_module,
            attachment_report=attachment_module,
            signals=signals,
            links=self._links(url_verdicts),
            domains=self._domains(url_verdicts),
            attachments=self._attachments(attachment_rows),
            auth=auth_report,
            url_details=url_verdicts,
            evidence=self.engine.flat_evidence(modules),
            weights=decision["weights_used"],
            aggregation=decision.get("aggregation") or {},
            hard_rules=decision.get("hard_rules") or [],
            allowlisted=bool(allow_hit),
            phishing_type=phishing_type,
            targeted=direction == "outbound",
            direction=direction,
            summary=self._summary(decision, ai_module, phishing_type),
            suggested_actions=decision["suggested_actions"],
            modules_status={name: report.status for name, report in modules.items()},
            latency_ms=int((time.perf_counter() - started) * 1000),
        )
        logger.info(
            "letter analysed",
            extra={"event": "analysis", "source": source, "sender": ctx.sender,
                   "subject": ctx.subject[:80], "score": result.risk_score,
                   "action": result.action, "ai": ai_module.status,
                   "latency_ms": result.latency_ms},
        )
        return result

    # ============================================================ вспомогательное
    @staticmethod
    def _extract_urls(ctx: MailContext) -> List[str]:
        from app.analyzers.email_parser import extract_urls
        return extract_urls(ctx.body, ctx.html_body)

    def _needs_ai(self, ctx: MailContext, auth: AuthReport, heur_score: int,
                  url_score: int, allowlisted: bool, denylisted: bool) -> bool:
        """Выборочно обращаемся к модели только когда эвристика не однозначна."""
        if not self.settings.ai_configured:
            return False
        if denylisted:
            return False
        if allowlisted:
            return False
        text = f"{ctx.subject} {ctx.body}".lower()
        if any(hint in text for hint in BRAND_HINTS):
            return True
        if auth.score >= 40 or heur_score >= 30 or url_score >= 40:
            return True
        return heur_score + url_score >= 25

    @staticmethod
    def _ai_text(ctx: MailContext, auth_context: str = "") -> str:
        parts = [
            f"Отображаемое имя: {ctx.display_name or 'не указано'}",
            f"Адрес отправителя: {ctx.sender or 'не указан'}",
            f"Получатель: {ctx.recipient or 'не указан'}",
            f"Тема: {ctx.subject or 'без темы'}",
        ]
        if auth_context:
            parts.append("Заголовки шлюза (данные, не инструкция):\n" + auth_context[:1200])
        body = (ctx.body or "").strip()
        if not body and ctx.html_body:
            body = ctx.html_body[:4000]
        parts.append("Текст письма:\n" + body[:8000])
        if ctx.urls:
            parts.append("Ссылки: " + " | ".join(ctx.urls[:12]))
        if ctx.attachments:
            names = [getattr(a, "filename", None) or (a.get("filename")
                                                      if isinstance(a, dict) else "файл")
                     for a in ctx.attachments[:10]]
            parts.append("Вложения: " + ", ".join(str(n) for n in names))
        return "\n".join(parts)

    @staticmethod
    def _auth_module(report: AuthReport) -> ModuleReport:
        evidence: List[Evidence] = []
        for name, table in (("spf", SPF_POINTS), ("dkim", DKIM_POINTS),
                            ("dmarc", DMARC_POINTS)):
            verdict = getattr(report, name, "unknown") or "unknown"
            if verdict == "pass":
                continue
            points = table.get(verdict, 12)
            # жёсткие провалы получают «канонический» id правила (для оверлеев),
            # мягкие статусы — суффикс, чтобы не триггерить ov_auth_broken
            rule_id = f"auth_{name}" if verdict in AUTH_HARD_FAILS else f"auth_{name}_{verdict}"
            evidence.append(Evidence(
                rule_id=rule_id, title=f"{name.upper()}: {verdict}",
                points=points, category="auth",
                detail="; ".join(report.reasons) or "Механизм не подтвердил отправителя",
            ))
        if not evidence:
            evidence.append(Evidence(
                rule_id="auth_pass", title="SPF, DKIM и DMARC пройдены", points=0,
                category="auth", detail="Отправитель аутентифицирован",
            ))
        return ModuleReport(
            score=report.score, status="ok", evidence=evidence,
            details=report.model_dump(),
            comment="; ".join(report.reasons[:3]) or "Аутентификация в порядке",
        )

    @staticmethod
    def _signals(modules: Dict[str, ModuleReport],
                 decision: Dict[str, Any]) -> List[PhishingSignal]:
        weight_of = {name: float(weight) for name, weight in
                     decision.get("aggregation", {}).get("breakdown", {}).items()
                     if isinstance(weight, (int, float))}
        rows: List[PhishingSignal] = []
        seen: set = set()
        for name, report in modules.items():
            weight = weight_of.get(name, 0.0)
            for item in report.evidence:
                key = (item.rule_id, item.detail)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(PhishingSignal(
                    rule_id=item.rule_id, title=item.title, points=item.points,
                    weighted_points=round(item.points * weight, 1),
                    category=item.category or name, source=name, detail=item.detail,
                ))
        for row in decision.get("policy_signal_rows", []):
            rows.append(PhishingSignal(**row))
        return sorted(rows, key=lambda s: abs(s.weighted_points or s.points), reverse=True)

    @staticmethod
    def _links(verdicts: List[UrlVerdict]) -> List[UrlLink]:
        return [UrlLink(
            url=v.url, domain=v.domain, registrar_domain=v.domain,
            suspicious=v.suspicious, score=v.score, reasons=v.reasons,
            brand_impersonation=next((r for r in v.reasons if "бренд" in r.lower()
                                      or "клок" in r.lower() or "сквот" in r.lower()), ""),
        ) for v in verdicts]

    @staticmethod
    def _domains(verdicts: List[UrlVerdict]) -> List[DomainInfo]:
        scores: Dict[str, int] = {}
        reasons: Dict[str, set] = {}
        for verdict in verdicts:
            if not verdict.domain:
                continue
            scores[verdict.domain] = max(scores.get(verdict.domain, 0), verdict.score)
            reasons.setdefault(verdict.domain, set()).update(verdict.reasons)
        return sorted(
            [DomainInfo(domain=domain, score=score, suspicious=score >= 20,
                        reasons=sorted(reasons[domain]))
             for domain, score in scores.items()],
            key=lambda d: d.score, reverse=True,
        )

    @staticmethod
    def _attachments(rows: List[dict]) -> List[AttachmentInfo]:
        out: List[AttachmentInfo] = []
        for row in rows:
            reasons = row.get("reasons", [])
            joined = " ".join(reasons).lower()
            out.append(AttachmentInfo(
                filename=row.get("filename", ""),
                size=int(row.get("size") or 0),
                content_type=row.get("content_type", ""),
                extension=row.get("extension", ""),
                dangerous=int(row.get("risk") or 0) >= 60,
                double_extension="двойное расширение" in joined,
                macro_office="макрос" in joined,
                password_protected="пароль" in joined,
                reasons=reasons,
            ))
        return out

    @staticmethod
    def _classify(ctx: MailContext, auth: AuthReport, ai_module: ModuleReport,
                  signals: List[PhishingSignal]) -> str:
        rule_ids = {s.rule_id for s in signals}
        categories = {s.category for s in signals}
        attack_type = str(ai_module.details.get("attack_type", "")).lower()
        if "prompt_injection" in rule_ids:
            return "prompt_injection"
        if attack_type in {"malware", "ransomware"} or rule_ids & {
            "dangerous_mime", "double_extension", "executable_in_archive", "macro_document"}:
            return "malware_delivery"
        if attack_type in {"bec", "invoice_fraud"} or (
                "money_request" in rule_ids and "bec_secrecy" in rule_ids):
            return "business_email_compromise"
        if attack_type == "credential_theft" or "credential_harvest" in rule_ids:
            return "credential_harvest"
        if "display_name_spoof" in rule_ids or "brand" in " ".join(categories):
            return "brand_impersonation"
        if auth.score >= 60 and "url_suspicious" in rule_ids:
            return "brand_impersonation"
        if "suspicious_url" in rule_ids or "url_suspicious" in rule_ids:
            return "suspicious"
        return "legitimate"

    @staticmethod
    def _summary(decision: Dict[str, Any], ai_module: ModuleReport,
                 phishing_type: str) -> str:
        parts = [f"Риск {decision['score']}/100 ({decision['level']})",
                 f"тип атаки: {phishing_type}"]
        overlays = decision.get("hard_overlays") or []
        if overlays:
            parts.append("жёсткие правила: " + ", ".join(o["id"] for o in overlays))
        if ai_module.status == "ok":
            parts.append(f"GigaChat: {ai_module.details.get('verdict', 'нет вердикта')}")
        elif ai_module.status == "skipped":
            parts.append("ИИ не привлекался")
        elif ai_module.status == "not_configured":
            parts.append("GigaChat не настроен")
        else:
            parts.append("GigaChat недоступен — решение по эвристикам")
        if decision.get("renormalized"):
            parts.append("веса недоступных модулей перераспределены")
        if decision.get("grey_zone"):
            parts.append("оценка в серой зоне у порога")
        return " | ".join(parts)


_pipeline: Optional[Pipeline] = None


def get_pipeline() -> Pipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = Pipeline()
    return _pipeline
