"""
Модуль 2. Проверка заголовков аутентификации отправителя (SPF / DKIM / DMARC).

Разбирает Authentication-Results, Received-SPF и связанные заголовки, которые
оставляет принимающий MTA. Это самый дешёвый и самый надёжный сигнал: письмо,
не прошедшее DMARC, почти всегда либо спойфинг, либо некорректно настроенный домен.

Поддерживаются типовые форматы:
    Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.org;
        dkim=pass header.d=example.org; dmarc=pass header.from=example.org
    Received-SPF: fail (google.com: domain of x@example.org does not designate ...)
"""
from __future__ import annotations

import re
from typing import Dict, List

from ..schemas import AuthReport

# Классификация вердиктов по «тяжести»
_SEVERITY = {
    "pass": 0,
    "none": 1,
    "temperror": 2,
    "policy": 3,
    "softfail": 4,
    "permerror": 5,
    "fail": 6,
}
_HARD_FAIL = {"fail", "permerror"}
_SOFT = {"softfail", "temperror", "policy"}

_MECH_RE = re.compile(
    r"(?i)\b(spf|dkim|dmarc|arc)\s*=\s*(pass|fail|softfail|permerror|temperror|none|policy)"
)
# Домены, которые MTA пишет рядом с вердиктом
_SPF_DOMAIN_RE = re.compile(
    r"(?i)smtp\.(?:mailfrom|helo|reverse-?path)\s*=\s*\"?([\w.-]+\.[a-z]{2,})"
)
_DKIM_DOMAIN_RE = re.compile(r"(?i)header\.d\s*=\s*\"?([\w.-]+\.[a-z]{2,})")
_DMARC_DOMAIN_RE = re.compile(
    r"(?i)dmarc[^;]*?(?:header\.from|\bd)\s*=\s*\"?([\w.-]+\.[a-z]{2,})"
)


def collect_auth_lines(headers: Dict[str, str]) -> List[str]:
    """Собирает все заголовки с результатами аутентификации в один список строк."""
    lines: List[str] = []
    for name, value in headers.items():
        low = name.lower()
        if low in ("authentication-results", "received-authentication-results",
                   "arc-authentication-results"):
            lines.append(value)
        elif low == "received-spf":
            # Received-SPF: fail (google.com: domain of ...) identity=...
            verdict = re.split(r"[;(]", value, 1)[0].strip().lower()
            if verdict:
                lines.append(f"spf={verdict}")
    return lines


def _worst_verdicts(auth_lines: List[str]) -> Dict[str, str]:
    """Если заголовков несколько (цепочка ретрансляции) — берём худший вердикт."""
    worst: Dict[str, str] = {}
    for line in auth_lines:
        for mech, verdict in _MECH_RE.findall(line):
            mech, verdict = mech.lower(), verdict.lower()
            if mech not in worst or _SEVERITY[verdict] > _SEVERITY[worst[mech]]:
                worst[mech] = verdict
    return worst


def _first(regex: re.Pattern, text: str) -> str:
    m = regex.search(text)
    return m.group(1).lower() if m else ""


def _score_label(verdict: str, fail_points: int, soft_points: int, unknown_points: int,
                 name: str, reasons: List[str]) -> int:
    if verdict == "pass":
        reasons.append(f"{name}: pass")
        return 0
    if verdict in _HARD_FAIL:
        reasons.append(f"{name}: {verdict} — проверка не пройдена")
        return fail_points
    if verdict in _SOFT:
        reasons.append(f"{name}: {verdict} — неопределённый/слабый результат")
        return soft_points
    if verdict == "none":
        reasons.append(f"{name}: {verdict} — механизм не настроен у отправителя")
        return unknown_points
    reasons.append(f"{name}: {verdict or 'не проверен'}")
    return unknown_points + 2


def _aligned(a: str, b: str) -> bool:
    return bool(a) and bool(b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def evaluate_auth(headers: Dict[str, str], sender_domain: str) -> AuthReport:
    """Возвращает отчёт по аутентификации с риском 0..100 (0 — всё чисто)."""
    auth_lines = collect_auth_lines(headers)
    reasons: List[str] = []

    if not auth_lines:
        return AuthReport(
            score=25,
            reasons=[
                "Заголовки Authentication-Results отсутствуют: MTA не проверял "
                "SPF/DKIM/DMARC — доверие к отправителю снижено"
            ],
        )

    joined = " ".join(auth_lines)
    verdicts = _worst_verdicts(auth_lines)
    spf = verdicts.get("spf", "unknown")
    dkim = verdicts.get("dkim", "unknown")
    dmarc = verdicts.get("dmarc", "unknown")

    spf_domain = _first(_SPF_DOMAIN_RE, joined)
    dkim_domain = _first(_DKIM_DOMAIN_RE, joined)
    dmarc_domain = _first(_DMARC_DOMAIN_RE, joined)

    score = 0
    score += _score_label(spf, 45, 22, 10, "SPF", reasons)
    score += _score_label(dkim, 35, 15, 12, "DKIM", reasons)
    score += _score_label(dmarc, 45, 20, 15, "DMARC", reasons)

    # Alignment: домен DMARC должен совпадать с доменом в From
    if dmarc_domain and sender_domain and not _aligned(dmarc_domain, sender_domain):
        score += 25
        reasons.append(
            f"Домен DMARC ({dmarc_domain}) не совпадает с доменом отправителя "
            f"({sender_domain}) — нарушение alignment, вероятный спойфинг"
        )

    # Конвертный домен SPF может принадлежать третьему лицу — мягкий сигнал
    if spf_domain and sender_domain and not _aligned(spf_domain, sender_domain):
        score += 12
        reasons.append(
            f"Конвертный домен SPF ({spf_domain}) отличается от домена в From ({sender_domain})"
        )

    return AuthReport(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        spf_domain=spf_domain,
        dkim_domain=dkim_domain,
        dmarc_domain=dmarc_domain,
        score=min(100, score),
        reasons=reasons,
    )
