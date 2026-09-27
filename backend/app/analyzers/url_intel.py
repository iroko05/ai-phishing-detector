"""
Анализ URL и доменной инфраструктуры.

Что умеет:
  * структурный разбор ссылки (IP-хост, punycode/IDN, credentials, нестандартный порт);
  * поиск брендов в чужих доменах и тайпосквоттинг по расстоянию Левенштейна;
  * гомоглифы (кириллица вместо латиницы) и punycode-подделки;
  * сокращатели ссылок, open-redirect параметры, «случайные» домены;
  * возраст домена через RDAP (кэшируется) и проверку разрешимости через DNS;
  * цепочку редиректов (куда реально ведёт ссылка).

Все внешние вызовы изолированы: сбой сети не должен ломать анализ —
в этом случае домен получает статус «не проверен», а не «безопасен».
"""
from __future__ import annotations

import ipaddress
import logging
import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

import httpx

from app.config import Settings, get_settings
from app.schemas import Evidence, ModuleReport, UrlVerdict

logger = logging.getLogger("gateway.url")

# ============================================================
# СПИСОК КОНТРОЛИРУЕМЫХ БРЕНДОВ (расширяется без правики логики)
# ============================================================
# brand_key -> (официальные домены, ключевые слова для поиска в чужих доменах)
BRANDS: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "Сбер": (("sberbank.ru", "sber.ru", "sberbank.com", "sbol.ru", "idle.ru"),
             ("sberbank", "sber", "sbol", "сбербанк", "сбер")),
    "Т-Банк": (("tbank.ru", "tinkoff.ru", "tsys.ru", "bank-tinkoff.ru", "tinkoffmobile.com"),
               ("tinkoff", "tbank", "т-банк", "тбанк", "тинькофф")),
    "Альфа-Банк": (("alfabank.ru", "alfa-bank.ru", "alfabank.com"),
                   ("alfabank", "alfa-bank", "альфабанк", "альфа-банк")),
    "ВТБ": (("vtb.ru", "vtbbank.ru", "vtbcare.ru"), ("vtb", "втб")),
    "Газпромбанк": (("gazprombank.ru", "gpb.ru"), ("gazprombank", "gazprom-bank", "газпромбанк")),
    "Промсвязьбанк": (("psbank.ru", "pscbl.mobi"), ("psbank", "psb", "промсвязьбанк")),
    "Совкомбанк": (("sovcombank.ru",), ("sovcombank", "совкомбанк")),
    "Ozon": (("ozon.ru", "ozon.travel", "ozonbank.ru"), ("ozon", "озон")),
    "Wildberries": (("wildberries.ru", "wb.ru"), ("wildberries", "wildberry", "вайлдбериз")),
    "Яндекс": (("yandex.ru", "yandex.com", "ya.ru", "yandex-team.ru", "yandexcloud.net"),
               ("yandex", "яндекс")),
    "Госуслуги": (("gosuslugi.ru", "uslugi.ru", "esia.gosuslugi.ru"),
                  ("gosuslugi", "gosuslug", "госуслуги", "esia")),
    "ФНС": (("nalog.ru", "nalog.gov.ru", "flk.nalog.ru"), ("nalog", "фнс", "налог")),
    "СБП": (("sbpl.ru",), ("sbpl", "сбп")),
    "Почта России": (("pochta.ru", "acs.pochta.ru"), ("pochta", "почта")),
    "Ростелеком": (("rt.ru", "rostelecom.ru"), ("rostelecom", "rostelecom", "ростелеком")),
    "МТС": (("mts.ru",), ("mts", "мтс")),
    "МегаФон": (("megafon.ru",), ("megafon", "мегафон")),
    "Билайн": (("beeline.ru", "bee.land"), ("beeline", "beelin", "билайн")),
    "Microsoft": (("microsoft.com", "live.com", "office.com", "microsoftonline.com",
                   "outlook.com", "login.microsoftonline.com"),
                  ("microsoft", "microsoftonline", "макрсофт", "маикрософт")),
    "Google": (("google.com", "gmail.com", "googleapis.com"), ("google", "gmail", "гугл")),
    "Apple": (("apple.com", "icloud.com"), ("apple", "icloud", "апл")),
    "Telegram": (("telegram.org", "t.me", "telegram.me"), ("telegram", "телеграм")),
    "1С-Битрикс": (("1c-bitrix.ru", "bitrix24.ru", "bitrix.info"), ("bitrix", "1c-bitrix", "битрикс")),
    "Kaspersky": (("kaspersky.ru", "kaspersky.com"), ("kaspersky", "касперский")),
}

# Легитимные сокращатели и редирект-сервисы (сами по себе — признак маскировки)
SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "shorturl.at", "cutt.ly", "bitly.su", "clck.ru", "rb.gy", "rebrand.ly",
    "s.id", "v.gd", "tiny.cc", "url shortened", "lnkd.in", "dlvr.it",
)

# Open-redirect параметры: домен может быть легитимным, но уводит на сторону
REDIRECT_PARAMS = ("url=", "redirect=", "redirect_uri=", "next=", "to=", "dest=",
                   "target=", "continue=", "returnurl=", "goto=")

SUSPICIOUS_TLDS = (
    "zip", "mov", "top", "xyz", "click", "link", "gq", "ml", "cf", "tk", "ga",
    "buzz", "work", "date", "racing", "download", "stream", "win", "bid", "loan",
    "country", "gdn", "men", "party", "science", "rest", "icu", "cyou", "monster",
    "quest", "beauty", "autos", "pics", "lifestyle", "lol", "sbs", "forwards",
)

SUSPICIOUS_PATH_WORDS = (
    "login", "signin", "sign-in", "logon", "auth", "verify", "verification", "confirm",
    "secure", "security", "account", "update", "password", "credential", "wallet",
    "payment", "invoice", "unlock", "access", "identity", "banking", "otp", "2fa",
    "webscr", "validation", "restore", "recover",
)

# Кириллические гомоглифы латинских букв
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "к": "k", "в": "b", "н": "h", "м": "m", "т": "t", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ԛ": "q", "ѡ": "w",
}

IP_HOST_RE = re.compile(r"https?://\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", re.I)
OBFUSCATED_IP_RE = re.compile(r"https?://(?:\d+|0x[0-9a-f]+|0o?[0-7]+)(?:\.|$)", re.I)


@dataclass
class DomainCacheEntry:
    age_days: Optional[int] = None
    resolved: Optional[bool] = None
    checked_at: float = 0.0
    rdap_failed: bool = False


@dataclass
class UrlIntel:
    """Клиент внешних проверок с кэшем по доменам."""

    settings: Settings = field(default_factory=get_settings)
    _domain_cache: Dict[str, DomainCacheEntry] = field(default_factory=dict, repr=False)

    # ---------- ПУБЛИЧНЫЙ API ----------
    def analyze(self, urls: List[str]) -> Tuple[ModuleReport, List[UrlVerdict]]:
        evidence: List[Evidence] = []
        verdicts: List[UrlVerdict] = []
        total = 0
        domains_seen: set[str] = set()

        for raw in urls:
            url = (raw or "").strip().strip("<>\"'(),;")
            if not url:
                continue
            verdict, points, reasons = self._analyze_one(url)
            verdicts.append(verdict)
            total += points
            if verdict.domain:
                domains_seen.add(verdict.domain)
            if reasons:
                evidence.append(Evidence(
                    rule_id="url_suspicious",
                    title=f"Подозрительная ссылка: {verdict.domain or url[:60]}",
                    points=points,
                    category="url",
                    detail="; ".join(reasons),
                ))

        # Доп. признак: много разных доменов в одном письме — типично для фишинга
        if len(domains_seen) >= 4:
            total += 15
            evidence.append(Evidence(
                rule_id="url_many_domains",
                title="Много разных доменов в письме",
                points=15,
                category="url",
                detail=f"Обнаружено доменов: {len(domains_seen)} ({', '.join(sorted(domains_seen)[:6])})",
            ))

        score = min(100, total)
        report = ModuleReport(
            score=score,
            status="ok" if urls else "skipped",
            evidence=evidence,
            details={
                "urls_checked": len(verdicts),
                "suspicious_urls_count": sum(1 for v in verdicts if v.suspicious),
                "typosquatting_detected": any("тайпосквот" in r.lower() or "гомоглиф" in r.lower()
                                              for v in verdicts for r in v.reasons),
                "domains": sorted(domains_seen),
            },
            comment="Анализ ссылочной инфраструктуры завершён",
        )
        return report, verdicts

    # ---------- ОДИН URL ----------
    def _analyze_one(self, url: str) -> Tuple[UrlVerdict, int, List[str]]:
        reasons: List[str] = []
        points = 0
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower().strip(".")
        path = (parsed.path or "") + ("?" + (parsed.query or "") if parsed.query else "")

        if not host:
            return UrlVerdict(url=url, suspicious=True, score=30,
                              reasons=["Не удалось разобрать ссылку"][:1]), 30, ["Некорректная ссылка"]

        domain = self._registrable_domain(host)

        # 1. Структурные аномалии
        points += self._check_structure(url, parsed, host, path, reasons)

        # 2. Бренд-анализ
        points += self._check_brand(host, domain, reasons)

        # 3. содержимое пути — только у неофициальных доменов: на официальной
        # странице входа слова auth/login/payments — норма, а не сигнал
        if not self._is_official_domain(domain):
            points += self._check_path(path, reasons)

        # 4. Внешние проверки (возраст/разрешимость)
        points += self._check_reputation(domain, reasons)

        # 5. Цепочка редиректов
        points += self._check_redirects(url, reasons)

        suspicious = points >= 20
        verdict = UrlVerdict(
            url=url[:500],
            suspicious=suspicious,
            score=min(100, points),
            domain=domain or host,
            reasons=reasons,
        )
        return verdict, points, reasons

    def _check_structure(self, url: str, parsed, host: str, path: str, reasons: List[str]) -> int:
        points = 0

        if IP_HOST_RE.search(url):
            reasons.append("Ссылка ведёт напрямую на IP-адрес")
            points += 45
        elif OBFUSCATED_IP_RE.match(url.replace("//", "//h", 1)):
            reasons.append("Признаки обфускации IP-адреса (десятичная/16-ричная запись)")
            points += 45
        else:
            try:
                ipaddress.ip_address(host)
                reasons.append("Хост является IP-адресом")
                points += 40
            except ValueError:
                pass

        if host.startswith("xn--") or ".xn--" in host or any(ord(c) > 127 for c in host):
            reasons.append("IDN/punycode-домен — возможная подделка символов (homograph)")
            points += 35

        if "@" in parsed.netloc:
            reasons.append("Ссылка содержит credentials/userinfo (@) — маскировка реального хоста")
            points += 40

        if parsed.scheme == "http":
            reasons.append("Незащищённый протокол http")
            points += 12
        elif parsed.scheme not in ("https",):
            reasons.append(f"Нестандартная схема {parsed.scheme}")
            points += 25

        if parsed.port and parsed.port not in (80, 443, 8080, 8443):
            reasons.append(f"Нестандартный порт {parsed.port}")
            points += 12

        labels = [l for l in host.split(".") if l]
        if len(labels) >= 5:
            reasons.append(f"Слишком вложенный хост ({len(labels)} уровней)")
            points += 15

        if host.count("-") >= 3:
            reasons.append("Избыточное количество дефисов в домене")
            points += 15

        if re.search(r"[0-9a-f]{16,}", host):
            reasons.append("Похоже на сгенерированный домен (случайная строка)")
            points += 30

        tld = labels[-1] if labels else ""
        if tld in SUSPICIOUS_TLDS:
            reasons.append(f"Недорогая/часто используемая в фишинге зона .{tld}")
            points += 18

        low = unquote(host + path).lower()
        for short in SHORTENERS:
            if short in low:
                reasons.append(f"Сокращатель ссылок {short} скрывает пункт назначения")
                points += 22
                break

        for param in REDIRECT_PARAMS:
            if param in (parsed.query or "").lower():
                reasons.append("Параметр open-redirect: редирект на сторонний ресурс")
                points += 20
                break

        return points

    def _check_brand(self, host: str, domain: str, reasons: List[str]) -> int:
        points = 0
        haystack = host.lower()

        for brand, (official, keywords) in BRANDS.items():
            official_norm = {self._registrable_domain(o) for o in official}

            # Ссылка ведёт на официальный домен бренда — снижаем риск
            if domain in official_norm:
                return 0

            for kw in keywords:
                if kw in haystack:
                    if any(h == kw or h.endswith("." + kw) for h in official_norm):
                        continue
                    # бренд живёт в чужом домене: sberbank-secure.evil.ru
                    reasons.append(
                        f"Упоминание бренда «{brand}» в неофициальном домене {domain or host} "
                        f"(официальные: {', '.join(sorted(official_norm)[:3])})"
                    )
                    points += 35

                    # Тайпосквоттинг: домен похож на официальный с точностью до 1-2 символов
                    for off in official_norm:
                        if self._looks_like_typosquat(off, domain):
                            reasons.append(
                                f"Тайпосквоттинг официального домена {off} (домен {domain})"
                            )
                            points += 40

                    # Гомоглифы: латиница заменена на кириллицу
                    if self._has_homoglyph(host):
                        reasons.append("В домене обнаружены гомоглифы (смешение кириллицы и латиницы)")
                        points += 35
                    break
        return points

    def _check_path(self, path: str, reasons: List[str]) -> int:
        low = unquote(path).lower()
        hits = [w for w in SUSPICIOUS_PATH_WORDS if w in low]
        if len(hits) >= 2:
            reasons.append(f"В пути ссылки ключевые слова авторизации: {', '.join(hits[:5])}")
            return 20
        if len(hits) == 1:
            reasons.append(f"В пути ссылки слово авторизации: {hits[0]}")
            return 8
        return 0

    def _is_official_domain(self, domain: str) -> bool:
        """Домен входит в официальный список одного из контролируемых брендов."""
        if not domain:
            return False
        for _brand, (official, _keywords) in BRANDS.items():
            if domain in {self._registrable_domain(o) for o in official}:
                return True
        return False

    # ---------- ВНЕШНИЕ ПРОВЕРКИ ----------
    def _check_reputation(self, domain: str, reasons: List[str]) -> int:
        if not domain or "." not in domain:
            return 0
        points = 0
        entry = self._domain_info(domain)

        if entry.resolved is False:
            reasons.append("Домен не разрешается в DNS (мёртвый/свежий домен)")
            points += 30

        if entry.age_days is not None:
            if entry.age_days <= self.settings.domain_age_suspicious_days:
                reasons.append(f"Домен зарегистрирован {entry.age_days} дн. назад — домен-однодневка")
                points += 35
            elif entry.age_days <= self.settings.domain_age_young_days:
                reasons.append(f"Домен молодой: {entry.age_days} дн. с момента регистрации")
                points += 15
        elif entry.rdap_failed:
            reasons.append("Не удалось определить возраст домена через RDAP")
            points += 5

        return points

    def _domain_info(self, domain: str) -> DomainCacheEntry:
        now = time.time()
        cached = self._domain_cache.get(domain)
        if cached and (now - cached.checked_at) < self.settings.rdap_cache_ttl:
            return cached

        entry = DomainCacheEntry(checked_at=now)
        if self.settings.dns_check_enabled:
            entry.resolved = self._dns_exists(domain)
        if self.settings.rdap_enabled and entry.resolved is not False:
            age, failed = self._rdap_age(domain)
            entry.age_days = age
            entry.rdap_failed = failed
        self._domain_cache[domain] = entry
        return entry

    @staticmethod
    def _dns_exists(domain: str) -> Optional[bool]:
        """True — разрешается, False — NXDOMAIN, None — резолвер недоступен."""
        try:
            import dns.resolver  # type: ignore

            resolver = dns.resolver.Resolver()
            resolver.lifetime = 2.0
            resolver.timeout = 2.0
            try:
                resolver.resolve(domain, "A")
                return True
            except dns.resolver.NXDOMAIN:
                return False
            except Exception:
                # SERFAIL/таймаут сами по себе ничего не значат
                return None
        except ImportError:
            import socket

            try:
                socket.getaddrinfo(domain, None)
                return True
            except socket.gaierror as exc:
                # -2/-3 = Name or service not known на glibc/Windows
                if getattr(exc, "errno", None) in (-2, -3, 11001):
                    return False
                return None
            except Exception:
                return None

    def _rdap_age(self, domain: str) -> Tuple[Optional[int], bool]:
        try:
            url = f"{self.settings.rdap_base_url}/{domain}"
            resp = httpx.get(
                url,
                timeout=self.settings.rdap_timeout,
                follow_redirects=True,
                headers={"Accept": "application/rdap+json, application/json"},
            )
            if resp.status_code != 200:
                return None, True
            data = resp.json()
            for event in data.get("events", []):
                if str(event.get("eventAction", "")).lower() in ("registration", "reg"):
                    raw = event.get("eventDate") or ""
                    ts = self._parse_ts(str(raw))
                    if ts:
                        return max(0, int((time.time() - ts) // 86400)), False
            return None, False
        except Exception as exc:  # сеть может быть недоступна — не роняем анализ
            logger.debug("RDAP failed for %s: %s", domain, exc)
            return None, True

    @staticmethod
    def _parse_ts(raw: str) -> Optional[float]:
        from datetime import datetime

        raw = raw.strip().replace("Z", "+00:00")
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(raw, fmt)
                if dt.tzinfo is None:
                    from datetime import timezone

                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue
        return None

    def _check_redirects(self, url: str, reasons: List[str]) -> int:
        if not self.settings.follow_redirects:
            return 0
        try:
            with httpx.Client(timeout=self.settings.redirect_timeout,
                              follow_redirects=True, max_redirects=5) as client:
                resp = client.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; PhishingGateway/3.0)"})
                chain = [str(r.url) for r in resp.history]
                if not chain:
                    return 0
                final_host = self._registrable_domain(urlparse(str(resp.url)).hostname or "")
                start_host = self._registrable_domain(urlparse(url).hostname or "")
                if final_host and start_host and final_host != start_host:
                    reasons.append(
                        f"Цепочка редиректов ({len(chain)}) ведёт на другой домен: {final_host}"
                    )
                    return 25
                return 10
        except Exception:
            return 0

    # ---------- УТИЛИТЫ ----------
    @staticmethod
    def _registrable_domain(host: str) -> str:
        """Грубый поиск «домена второго уровня» — без внешних зависимостей."""
        if not host:
            return ""
        labels = [l for l in host.lower().strip(".").split(".") if l]
        if len(labels) <= 2:
            return ".".join(labels)
        # поддержка двухчастных публичных суффиксов для самых частых зон
        two_part = ("com.ru", "net.ru", "org.ru", "pp.ru", "ac.ru", "edu.ru", "co.uk",
                    "org.uk", "com.br", "co.jp", "com.ua", "com.kz", "co.il", "com.tr")
        suffix = ".".join(labels[-2:])
        if suffix in two_part:
            return ".".join(labels[-3:])
        return suffix

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a or not b:
            return max(len(a), len(b))
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i]
            for j, cb in enumerate(b, 1):
                cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            prev = cur
        return prev[-1]

    def _looks_like_typosquat(self, official: str, candidate: str) -> bool:
        """Похож ли candidate на official с 1-2 правками, но не равен ему."""
        if not candidate or candidate == official:
            return False
        off_root = official.split(".")[0]
        cand_root = candidate.split(".")[0]
        if len(off_root) < 4:
            return False
        # бренд внутри чужого домена: sberbank.security-alert.top
        if off_root in cand_root and cand_root != off_root:
            return True
        distance = self._levenshtein(off_root, cand_root)
        allowed = 1 if len(off_root) <= 7 else 2
        return 0 < distance <= allowed

    @staticmethod
    def _has_homoglyph(host: str) -> bool:
        if not host:
            return False
        has_cyr = any("а" <= ch <= "я" or ch in "ёЁІі" for ch in host)
        has_lat = any("a" <= ch.lower() <= "z" for ch in host)
        if has_cyr and has_lat:
            return True
        # punycode-домен, декодируемый в смесь алфавитов
        if host.startswith("xn--") or ".xn--" in host:
            try:
                decoded = host.encode("ascii").decode("idna")
                return any("а" <= ch <= "я" for ch in decoded) and any(
                    "a" <= ch.lower() <= "z" for ch in decoded
                )
            except Exception:
                return True
        return False
