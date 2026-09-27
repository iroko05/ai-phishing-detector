"""
Движок принятия решения: взвешенная агрегация модулей + политика шлюза.

Почему не «сумма баллов», как было в v1:
  * модули имеют разную надёжность — сломанный SPF важнее восклицательных знаков;
  * каждый модуль отдаёт нормированную оценку 0..100, итог = Σ(wᵢ·sᵢ)/Σ(wᵢ)
    только по ДОСТУПНЫМ модулям: при отказе GigaChat его вес не «сгорает»,
    а пропорционально перераспределяется — вердикт не сползает в «безопасно»;
  * жёсткие оверлеи не дают «размазать» однозначные сигналы (эксплойт во вложении,
    prompt-injection, домен-клок банка при непройденном SPF).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from app.analyzers.heuristics import MailContext
from app.config import Settings, get_settings
from app.schemas import Evidence, ModuleReport
from app.storage.stores import PatternStore

logger = logging.getLogger("gateway.scoring")

# Ключи совпадают с module_weights в конфигурации.
MODULES = ("heuristics", "urls", "auth", "attachments", "ai")

ACTION_LEVEL = {
    "allow": "low",
    "warn": "medium",
    "hold": "high",
    "quarantine": "critical",
    "block": "critical",
}

ACTION_ORDER = ["allow", "warn", "hold", "quarantine", "block"]

SUGGESTIONS: Dict[str, List[str]] = {
    "allow": ["Доставить письмо", "Наблюдать за доменом отправителя"],
    "warn": [
        "Доставить с заголовком X-Phishing-Score",
        "Показать пользователю предупреждение о непройденной аутентификации",
    ],
    "hold": [
        "Задержать доставку до подтверждения администратором",
        "Проверить домен отправителя вручную",
        "Уточнить у получателя, ожидает ли он такое письмо",
    ],
    "quarantine": [
        "Поместить письмо в карантин и уведомить аналитика",
        "Заблокировать ссылки и вложения до разбора",
        "Добавить домен в denylist при подтверждении атаки",
    ],
    "block": [
        "Отклонить письмо на уровне MTA",
        "Добавить домен/сеть отправителя в denylist",
        "Проверить почту на предыдущие письма с этого источника",
    ],
}

# Имена правил, которые в одиночку тянут вердикт вверх (используются оверлеями).
HARD_BLOCK_RULES = {
    "prompt_injection", "dangerous_mime", "double_extension", "executable_in_archive",
}
HARD_QUARANTINE_RULES = {
    "macro_document", "password_protected_archive", "html_attachment",
    "credential_harvest", "bec_secrecy", "money_request",
}


def _rule_ids(report: Optional[ModuleReport]) -> set[str]:
    return {e.rule_id for e in (report.evidence if report else [])}


class ScoringEngine:
    def __init__(self, settings: Optional[Settings] = None,
                 patterns: Optional[PatternStore] = None) -> None:
        self.settings = settings or get_settings()
        self.patterns = patterns
        self.weights = self.settings.module_weights
        self.thresholds = self.settings.thresholds
        self.grey_zone = self.settings.grey_zone

    # ------------------------------------------------------- списки политик
    def allowlist_match(self, sender_domain: str, sender: str) -> Optional[Dict[str, Any]]:
        if not self.patterns:
            return None
        entry = self.patterns.match(sender_domain or sender, kind="allow")
        if not entry:
            return None
        return {"pattern": entry.pattern, "note": entry.note, "kind": "allow"}

    def denylist_match(self, ctx: MailContext) -> Optional[Dict[str, Any]]:
        """Чёрный список: по домену отправителя и regex по теме/имени/телу."""
        if not self.patterns:
            return None
        entry = self.patterns.match(ctx.sender_domain or ctx.sender, kind="deny")
        if entry:
            return {"pattern": entry.pattern, "note": entry.note, "kind": "deny_domain"}
        text = f"{ctx.subject}\n{ctx.display_name}\n{ctx.body[:4000]}"
        regex_hit = self.patterns.regex_match(text, kind="deny")
        if regex_hit:
            return {"pattern": regex_hit.pattern, "note": regex_hit.note, "kind": "deny_regex"}
        return None

    # ------------------------------------------------------- агрегация
    def aggregate(self, modules: Dict[str, ModuleReport]) -> Dict[str, Any]:
        used_weight = 0.0
        weighted_sum = 0.0
        breakdown: Dict[str, Dict[str, Any]] = {}
        skipped: List[str] = []

        for name in MODULES:
            report = modules.get(name)
            if report is None:
                continue
            weight = float(self.weights.get(name, 0.0))
            if report.status != "ok" or weight <= 0:
                skipped.append(name)
                breakdown[name] = {"score": report.score, "weight": weight,
                                   "contribution": 0.0, "status": report.status,
                                   "included": False}
                continue
            used_weight += weight
            weighted_sum += weight * report.score
            breakdown[name] = {"score": report.score, "weight": round(weight, 3),
                               "contribution": round(weight * report.score, 2),
                               "status": "ok", "included": True}

        total_weight = sum(self.weights.get(n, 0.0) for n in MODULES) or 1.0
        if used_weight <= 0:
            return {"score": 0, "used_weight": 0.0, "breakdown": breakdown,
                    "skipped_modules": skipped, "renormalized": False,
                    "weights_used": {}, "note": "Ни один модуль не отработал"}

        score = weighted_sum / used_weight
        weights_used = {n: round(b["weight"] / used_weight, 3)
                        for n, b in breakdown.items() if b["included"]}
        renormalized = abs(used_weight - total_weight) > 1e-6
        return {
            "score": int(round(max(0.0, min(100.0, score)))),
            "used_weight": round(used_weight, 3),
            "breakdown": breakdown,
            "skipped_modules": skipped,
            "renormalized": renormalized,
            "weights_used": weights_used,
            "note": "Веса недоступных модулей перераспределены"
                    if renormalized else "Все модули отработали",
        }

    # ------------------------------------------------------- сигналы
    @staticmethod
    def collect_signals(modules: Dict[str, ModuleReport]) -> Dict[str, bool]:
        """Плоская карта сработавших правил — используется оверлеями."""
        signals: Dict[str, bool] = {}
        for report in modules.values():
            if report.status != "ok":
                continue
            for evidence in report.evidence:
                if evidence.points > 0:
                    signals[evidence.rule_id] = True
        return signals

    def _overlays(self, signals: Dict[str, bool],
                  modules: Dict[str, ModuleReport]) -> List[Tuple[str, str, str]]:
        """Жёсткие правила: (id, объяснение, минимальное действие)."""
        hits: List[Tuple[str, str, str]] = []

        if signals.get("prompt_injection"):
            hits.append(("ov_injection",
                         "В тексте письма попытка инструктировать ИИ-ассистента "
                         "(prompt-injection)", "block"))
        if {"dangerous_mime", "double_extension", "executable_in_archive"} & set(signals):
            hits.append(("ov_payload",
                         "Во вложении исполняемая или замаскированная полезная нагрузка",
                         "block"))
        if signals.get("credential_harvest") and signals.get("url_suspicious"):
            hits.append(("ov_credential_url",
                         "Запрос учётных данных по подозрительной ссылке", "quarantine"))
        if signals.get("money_request") and (signals.get("bec_secrecy")
                                             or signals.get("bypass_process")):
            hits.append(("ov_bec",
                         "BEC: платёж в обход процедур с просьбой о секретности",
                         "quarantine"))
        if signals.get("display_name_spoof") and signals.get("url_suspicious"):
            hits.append(("ov_spoofed_brand",
                         "Отображаемое имя выдаёт известный бренд при подозрительных ссылках",
                         "quarantine"))
        auth_failed = [name for name in ("auth_dmarc", "auth_spf", "auth_dkim")
                       if signals.get(name)]
        if len(auth_failed) >= 2:
            hits.append(("ov_auth_broken",
                         "Не пройдены две и более проверки подлинности отправителя", "hold"))
        return hits

    # ------------------------------------------------------- вердикт
    def decide(self, modules: Dict[str, ModuleReport], ctx: MailContext, *,
               allow_hit: Optional[Dict[str, Any]] = None,
               deny_hit: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        aggregation = self.aggregate(modules)
        signals = self.collect_signals(modules)
        overlays = self._overlays(signals, modules)

        score = aggregation["score"]
        action = self._band(score)
        reason_parts: List[str] = [aggregation["note"]]

        if deny_hit:
            action = "block"
            score = max(score, self.thresholds["block"])
            reason_parts.append(f"Источник {deny_hit['pattern']} в чёрном списке шлюза")

        order = {name: index for index, name in enumerate(ACTION_ORDER)}
        for _ov_id, description, floor in overlays:
            if order[floor] > order[action]:
                action = floor
            reason_parts.append(description)
            floor_score = (self.thresholds["block"] if floor == "block"
                           else self.thresholds["quarantine"] if floor == "quarantine"
                           else self.thresholds["hold"])
            score = max(score, min(100, floor_score))

        if allow_hit and not deny_hit and not overlays:
            action = "allow"
            reason_parts.append(
                f"Отправитель {allow_hit['pattern']} в белом списке "
                f"({allow_hit.get('note') or 'без примечания'})")

        grey = self._in_grey_zone(score)
        if grey and action in ("warn", "hold"):
            reason_parts.append(
                f"Оценка в серой зоне ±{self.grey_zone} от порога — решение на границе")

        confidence = self._confidence(modules, overlays, score, allowlisted=bool(allow_hit))
        level = ACTION_LEVEL[action]
        reason = self._build_reason(action, level, reason_parts, modules)

        return {
            "score": int(score),
            "action": action,
            "level": level,
            "reason": reason,
            "confidence": confidence,
            "weights_used": aggregation["weights_used"],
            "renormalized": aggregation["renormalized"],
            "aggregation": aggregation,
            "hard_overlays": [{"id": oid, "description": desc, "action": floor}
                              for oid, desc, floor in overlays],
            "policy_signals": {
                "signals": sorted(k for k, v in signals.items() if v),
                "allowlisted": bool(allow_hit),
                "denylisted": bool(deny_hit),
                "grey_zone": grey,
            },
            "policy_signal_rows": [
                {"rule_id": oid, "title": desc, "points": 0, "category": "policy",
                 "source": "policy", "detail": f"Минимальное действие: {floor}"}
                for oid, desc, floor in overlays
            ],
            "suggested_actions": SUGGESTIONS[action],
            "grey_zone": grey,
        }

    # ------------------------------------------------------- helpers
    def _band(self, score: int) -> str:
        thresholds = self.thresholds
        if score >= thresholds["block"]:
            return "block"
        if score >= thresholds["quarantine"]:
            return "quarantine"
        if score >= thresholds["hold"]:
            return "hold"
        if score >= thresholds["warn"]:
            return "warn"
        return "allow"

    def _in_grey_zone(self, score: int) -> bool:
        return any(abs(score - self.thresholds[key]) <= self.grey_zone
                   for key in ("warn", "hold", "quarantine", "block"))

    @staticmethod
    def _confidence(modules: Dict[str, ModuleReport], overlays: List[Tuple[str, str, str]],
                    score: int, *, allowlisted: bool) -> float:
        active = [r for r in modules.values() if r.status == "ok"]
        coverage = len(active) / max(1, len(MODULES))
        confidence = 0.30 + 0.40 * coverage + 0.20 * (min(score, 100) / 100.0)
        if overlays:
            confidence = max(confidence, 0.9)
        if allowlisted:
            confidence = max(confidence, 0.95)
        return round(min(confidence, 0.98), 2)

    @staticmethod
    def _build_reason(action: str, level: str, parts: List[str],
                      modules: Dict[str, ModuleReport]) -> str:
        prefix = {
            "allow": "Доставить", "warn": "Доставить с предупреждением",
            "hold": "Задержать", "quarantine": "Карантин", "block": "Отклонить",
        }[action]
        details: List[str] = []
        for name in MODULES:
            report = modules.get(name)
            if not report or report.status != "ok":
                continue
            top = sorted(report.evidence, key=lambda e: abs(e.points), reverse=True)[:2]
            for evidence in top:
                if evidence.points > 0:
                    details.append(f"{evidence.title} (+{evidence.points})")
        unique: List[str] = []
        for item in parts + details:
            if item and item not in unique:
                unique.append(item)
        return f"{prefix} ({level}): " + "; ".join(unique[:5])

    def flat_evidence(self, modules: Dict[str, ModuleReport]) -> List[Evidence]:
        """Все доказательства с пересчитанным взвешенным вкладом."""
        out: List[Evidence] = []
        for name in MODULES:
            report = modules.get(name)
            if not report:
                continue
            weight = float(self.weights.get(name, 0.0))
            for item in report.evidence:
                item.source = name
                item.weight = round(weight, 3)
                item.weighted_points = round(item.points * weight, 1)
                out.append(item)
        return sorted(out, key=lambda e: abs(e.weighted_points or e.points), reverse=True)


def build_engine(settings: Optional[Settings] = None,
                 patterns: Optional[PatternStore] = None) -> ScoringEngine:
    return ScoringEngine(settings=settings,
                         patterns=patterns or PatternStore())
