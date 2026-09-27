"""
Модуль 1. Эвристический анализатор содержимого письма.

Правила описаны декларативно в реестре RULES: каждое правило имеет вес, категорию
и человекочитаемое описание. Это даёт объяснимость вердикта (SOC-аналитик видит,
что именно подняло риск) и позволяет выгружать каталог правил через API.

Веса подобраны так, чтобы одиночное «мягкое» правило не блокировало письмо,
а комбинация типичных признаков фишинга набирала порог карантина.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ..schemas import Evidence

# ============================================================
# КОНТЕКСТ ПИСЬМА ДЛЯ ПРАВИЛ
# ============================================================
@dataclass
class MailContext:
    sender: str = ""
    sender_local: str = ""
    sender_domain: str = ""
    display_name: str = ""
    recipient: str = ""
    recipient_local: str = ""
    subject: str = ""
    body: str = ""
    html_body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    attachments: List[dict] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)

    @property
    def plain_text(self) -> str:
        if self.body:
            return self.body
        if self.html_body:
            return strip_html(self.html_body)
        return ""

    @property
    def full_text(self) -> str:
        return f"{self.subject}\n{self.plain_text}".lower()


def strip_html(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"[ \t\r\f\v]+", " ", text).strip()


# ============================================================
# РЕЕСТР ПРАВИЛ
# ============================================================
RuleMatcher = Callable[[MailContext], Optional[str]]


@dataclass
class Rule:
    id: str
    title: str
    points: int
    category: str
    description: str
    matcher: RuleMatcher


RULES: List[Rule] = []


def rule(rule_id: str, title: str, points: int, category: str, description: str):
    def decorator(func: RuleMatcher) -> RuleMatcher:
        RULES.append(Rule(rule_id, title, points, category, description, func))
        return func

    return decorator


def _any(pattern: str, text: str) -> Optional[re.Match]:
    return re.search(pattern, text, re.IGNORECASE | re.DOTALL)


# ------------------------------------------------------------
# СОЦИАЛЬНАЯ ИНЖЕНЕРИЯ: СРОЧНОСТЬ И ДАВЛЕНИЕ
# ------------------------------------------------------------
URGENCY_RE = (
    r"\b(срочно|немедленно|незамедлительно|в течение\s+\d+\s*(минут|часов|дней?)|"
    r"до конца (дня|сегодня)|последн(ий|яя) (возможность|день)|urgent(ly)?|"
    r"immediately|expire[sd]?|истека(ет|ет срок)|в течение часа)\b"
)
THREAT_RE = (
    r"(заблокир|приостанов|ограничен|будет отключен|удал(им|ён)|"
    r"утратите доступ|потеря(ете|ете доступ)|account (will be )?(suspend|closed|locked)|"
    r"your account has been)"
)


@rule("urgency_pressure", "Давление срочностью", 18, "social_engineering",
      "В тексте присутствуют формулировки искусственного дедлайна.")
def r_urgency(ctx: MailContext) -> Optional[str]:
    m = _any(URGENCY_RE, ctx.full_text)
    return f"Найдена формулировка давления: «{m.group(0)[:60]}»" if m else None


@rule("threat_block", "Угроза блокировки/потери доступа", 22, "social_engineering",
      "Классическая запугивающая тактика фишинга.")
def r_threat(ctx: MailContext) -> Optional[str]:
    m = _any(THREAT_RE, ctx.full_text)
    return f"Обнаружена угроза: «{m.group(0)[:60]}»" if m else None


@rule("exclaim_overload", "Избыточная эмоциональность", 8, "social_engineering",
      "Множественные восклицательные знаки и КАПС в теле письма.")
def r_exclaim(ctx: MailContext) -> Optional[str]:
    text = ctx.plain_text
    if text.count("!") > 3 or (len(text) > 40 and re.search(r"[А-ЯA-Z]{6,}", text)):
        return "Повышенная эмоциональность текста (! / КАПС)"
    return None


# ------------------------------------------------------------
# УЧЁТНЫЕ ДАННЫЕ И ДЕНЬГИ
# ------------------------------------------------------------
CRED_RE = (
    r"(подтвердите|введите|сообщите|пришлите|продиктуйте|обновите).{0,40}"
    r"(пароль|логин|учётн\w+ данные|код (из sms|подтверждения)|2fa|otp|cvv|cvc|"
    r"пин-?код|секретн\w+ слово|password|credentials|one-?time code)"
)
MONEY_RE = (
    r"(перевод(е)? (на|денег|средств)|оплатите|срочная оплата|счёт на оплату|invoice|"
    r"подарочн\w+ карт\w+|gift ?card|криптовалют|usdt|btc|смени(ли|ли)? реквизит\w+|"
    r"новые реквизит\w+|изменились реквизит\w+|перечисли\w* средств\w*)"
)


@rule("credential_harvest", "Запрос учётных данных", 30, "credentials",
      "Прямая или косвенная просьба передать пароль, код 2FA или персональные данные.")
def r_credentials(ctx: MailContext) -> Optional[str]:
    m = _any(CRED_RE, ctx.full_text)
    return f"Запрос учётных данных: «{m.group(0)[:70]}»" if m else None


@rule("money_request", "Денежный запрос / смена реквизитов", 32, "bec",
      "Признак BEC-схемы: просьба оплатить счёт, перевести средства или сменить реквизиты.")
def r_money(ctx: MailContext) -> Optional[str]:
    m = _any(MONEY_RE, ctx.full_text)
    return f"Денежный манёвр: «{m.group(0)[:70]}»" if m else None


@rule("bec_secrecy", "Просьба сохранить секретность", 26, "bec",
      "Просьба не обсуждать запрос с коллегами или руководством — маркер CEO-fraud.")
def r_secrecy(ctx: MailContext) -> Optional[str]:
    m = _any(
        r"(не (говори|сообщай|говорите|сообщайте)|никому не (говори|сообщай|знает)|"
        r"это (секретно|конфиденциально|между нами)|в строгой тайне|в тайне от|"
        r"keep (this|it) (confidential|between us)|don'?t tell anyone)",
        ctx.full_text,
    )
    return f"Просьба о секретности: «{m.group(0)[:70]}»" if m else None


@rule("bypass_process", "Обход стандартных процедур", 18, "bec",
      "Просьба согласовать вне регламента / «по-быстрому», минуя бухгалтерию или ИБ.")
def r_bypass(ctx: MailContext) -> Optional[str]:
    m = _any(
        r"(в обход|без согласования|без заявки|по-быстрому|быстро согласу|в порядке исключения|"
        r"не (надо|нужно) оформлять|skip (the )?(normal|usual) process|as a favor)",
        ctx.full_text,
    )
    return f"Просьба обойти процедуру: «{m.group(0)[:70]}»" if m else None


@rule("authority_impersonation", "Апелляция к авторитету", 14, "bec",
      "Ссылки на руководство/ИБ/банк как основание не задавать вопросов.")
def r_authority(ctx: MailContext) -> Optional[str]:
    m = _any(
        r"(по поручению|мне поручил\w*|генеральн\w+ директор|финансов\w+ директор|"
        r"главбух|главный бухгалтер|служба безопасности|ит-поддержк|техподдержк|"
        r"the (ceo|cfo|cto)|board of directors)",
        ctx.full_text,
    )
    return f"Апелляция к авторитету: «{m.group(0)[:70]}»" if m else None


# ------------------------------------------------------------
# ЛИНГВИСТИКА И ОФОРМЛЕНИЕ
# ------------------------------------------------------------
@rule("generic_greeting", "Обезличенное обращение", 12, "linguistic",
      "Обращения «уважаемый клиент/сотрудник» вместо имени получателя.")
def r_greeting(ctx: MailContext) -> Optional[str]:
    m = _any(
        r"(уважаемый (клиент|сотрудник|пользователь|абонент)|дорогой (клиент|пользователь)|"
        r"dear (customer|user|valued|sir)|уважаемые клиенты)",
        ctx.full_text,
    )
    return f"Обезличенное обращение: «{m.group(0)[:50]}»" if m else None


@rule("mismatched_greeting", "Несовпадение имени получателя", 16, "linguistic",
      "В обращении указано имя, отличное от имени/адреса получателя.")
def r_mismatch_greeting(ctx: MailContext) -> Optional[str]:
    if not ctx.recipient_local:
        return None
    m = _any(r"(уважаемый|дорогой|дорогая|уважаемая)\s+([а-яa-z]{3,20})", ctx.full_text)
    if not m:
        return None
    named = m.group(2).lower()
    local = ctx.recipient_local.lower()
    name_part = re.split(r"[._\-0-9]", local)[0]
    if name_part and name_part[:4] not in named and named[:4] not in name_part:
        return f"Обращение «{m.group(2)}» не совпадает с получателем {ctx.recipient}"
    return None


@rule("latin_cyrillic_mix", "Смешение кириллицы и латиницы в словах", 16, "linguistic",
      "Гибрид кириллических и латинских букв внутри доменов/слов — признак гомоглиф-атаки.")
def r_mix(ctx: MailContext) -> Optional[str]:
    hits = re.findall(r"(?i)\b(?=[a-zа-я]*[a-z])(?=[a-zа-я]*[а-я])[a-zа-я]{5,}\b", ctx.full_text)
    # Отбрасываем нормальные заимствования типа "IT-отдел", ищем поддельные бренды
    suspicious = [h for h in hits if re.search(r"[a-zа-я]{2,}[а-яa-z]{2,}", h)][:3]
    return f"Подозрительные смешанные написания: {', '.join(suspicious)}" if suspicious else None


@rule("poor_literacy", "Языковые аномалии", 10, "linguistic",
      "Нетипичные обороты и ошибки, характерные для машинного перевода.")
def r_literacy(ctx: MailContext) -> Optional[str]:
    patterns = (
        r"\b(просим вас принять к сведению|будьте уверены|для избежания|"
        r"нажмите сюда для продолжения|в целях безопасности ваш)\b"
    )
    m = _any(patterns, ctx.full_text)
    return f"Нетипичная формулировка: «{m.group(0)[:60]}»" if m else None


@rule("prompt_injection", "Попытка prompt-injection", 34, "ai_abuse",
      "В тексте письма содержатся инструкции для ИИ-модели — попытка обмануть ИИ-анализ.")
def r_injection(ctx: MailContext) -> Optional[str]:
    m = _any(
        r"(игнорируй(те)? (все )?(предыдущие|выше) инструкции|ignore (all )?(previous|above) "
        r"instructions|system prompt|ты (языковая )?модель|пометь (это )?письмо как "
        r"(safe|безопасн)|consider this email (safe|legitimate)|disregard (the )?system)",
        ctx.full_text,
    )
    return f"Скрытая инструкция для ИИ: «{m.group(0)[:70]}»" if m else None


# ------------------------------------------------------------
# ВЛОЖЕНИЯ
# ------------------------------------------------------------
DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".ps1", ".bat", ".cmd",
    ".hta", ".lnk", ".msi", ".com", ".pif", ".jar", ".reg", ".iso", ".img", ".cab",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".gz4", ".ace"}
DOC_EXT = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf"}


# Правила по вложениям вынесены в analyzers/attachments.py — там они дают
# пофайловые вердикты (attachment_report), и считать их дважды незачем.
ATTACHMENT_EXT_CATEGORIES = {
    "dangerous": sorted(DANGEROUS_EXT),
    "macro": sorted(MACRO_EXT),
    "archive": sorted(ARCHIVE_EXT),
    "document": sorted(DOC_EXT),
}


# ------------------------------------------------------------
# HTML-АНАЛИЗ
# ------------------------------------------------------------
@rule("html_link_mismatch", "Текст ссылки не совпадает с адресом", 32, "html",
      "Отображаемый текст ссылки ведёт на другой домен (классика фишинга).")
def r_link_mismatch(ctx: MailContext) -> Optional[str]:
    if not ctx.html_body:
        return None
    pairs = re.findall(r"(?is)<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", ctx.html_body)
    mismatches = []
    for href, label in pairs:
        label_text = strip_html(label)
        m = re.search(r"https?://([^/\s>]+)", label_text)
        if m:
            shown = m.group(1).lower()
            real = re.search(r"https?://([^/\s]+)", href)
            if real and real.group(1).lower() != shown and not real.group(1).lower().endswith(shown):
                mismatches.append(f"{shown} → {real.group(1)[:40]}")
    return f"Несоответствие ссылок: {'; '.join(mismatches[:3])}" if mismatches else None


@rule("html_hidden_content", "Скрытый HTML-контент", 26, "html",
      "Скрытый текст/невидимые элементы — обход фильтров и сокрытие реального адреса.")
def r_hidden(ctx: MailContext) -> Optional[str]:
    if not ctx.html_body:
        return None
    if re.search(r"(?i)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|max-height\s*:\s*0)", ctx.html_body):
        return "В письме есть скрытые блоки HTML"
    if re.search(r"(?i)color\s*:\s*(#fff\b|#ffffff|white)", ctx.html_body) and len(ctx.html_body) > 400:
        return "Возможен текст белого цвета на белом фоне"
    return None


@rule("html_form_action", "Внешняя HTML-форма в письме", 30, "html",
      "Форма ввода с action на внешний домен — прямой сбор учётных данных.")
def r_form(ctx: MailContext) -> Optional[str]:
    if not ctx.html_body:
        return None
    m = re.search(r"(?is)<form[^>]+action=[\"']([^\"']+)", ctx.html_body)
    if m:
        return f"Форма отправляет данные на {m.group(1)[:60]}"
    if re.search(r"(?i)<input[^>]+type=[\"']password", ctx.html_body):
        return "В письме присутствует поле ввода пароля"
    return None


@rule("html_base_tag", "Подмена базового URL через <base>", 28, "html",
      "Тег <base> перенаправляет все относительные ссылки письма на чужой домен.")
def r_base_tag(ctx: MailContext) -> Optional[str]:
    if not ctx.html_body:
        return None
    m = re.search(r"(?is)<base[^>]+href=[\"']([^\"']+)", ctx.html_body)
    return f"Установлен <base href='{m.group(1)[:60]}'>" if m else None


@rule("html_remote_tracking", "Удалённые изображения/трекинг", 8, "html",
      "Письмо подгружает внешние изображения — используется для подтверждения активности ящика.")
def r_tracking(ctx: MailContext) -> Optional[str]:
    if not ctx.html_body:
        return None
    if len(re.findall(r"(?is)<img[^>]+src=[\"']https?://", ctx.html_body)) >= 1:
        return "Внешние изображения подгружаются с удалённого сервера"
    return None


# ------------------------------------------------------------
# ЗАГОЛОВКИ И КОНВЕРТ
# ------------------------------------------------------------
@rule("reply_to_mismatch", "Reply-To не совпадает с отправителем", 28, "envelope",
      "Ответ уходит на другой адрес — классический приём перехвата переписки.")
def r_reply_to(ctx: MailContext) -> Optional[str]:
    reply_to = ctx.headers.get("reply-to", "")
    if not reply_to:
        return None
    m = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", reply_to)
    if not m:
        return None
    rt_domain = m.group(1).lower()
    if ctx.sender_domain and rt_domain != ctx.sender_domain and not rt_domain.endswith("." + ctx.sender_domain):
        return f"Reply-To: {reply_to} ≠ домен отправителя {ctx.sender_domain}"
    return None


@rule("display_name_spoof", "Отображаемое имя имитирует легитимный источник", 26, "envelope",
      "Имя отправителя содержит бренд/подразделение, домен при этом не принадлежит ему.")
def r_display_spoof(ctx: MailContext) -> Optional[str]:
    if not ctx.display_name:
        return None
    name = ctx.display_name.lower()
    brands = ("сбер", "sber", "альфа", "alfa", "втб", "gazprom", "газпром", "t-bank", "т-банк",
              "тинькофф", "tinkoff", "microsoft", "майл", "yandex", "яндекс", "госуслуги",
              "налог", "полиция", "банк", "support", "security", "безопасность", "ит")
    looks_brand = any(b in name for b in brands)
    official = any(b in ctx.sender_domain.lower() for b in brands)
    if looks_brand and not official:
        return f"Имя «{ctx.display_name}» не подтверждается доменом {ctx.sender_domain}"
    return None


@rule("free_mail_corporate", "Корпоративный вид с бесплатной почты", 20, "envelope",
      "Письмо «от имени компании» приходит с публичного почтового сервиса.")
def r_free_mail(ctx: MailContext) -> Optional[str]:
    free = ("gmail.com", "mail.ru", "yandex.ru", "inbox.ru", "list.ru", "bk.ru",
            "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com")
    if ctx.sender_domain in free:
        name = (ctx.display_name or "").lower()
        if re.search(r"(банк|bank|support|поддержк|служб|отдел|компан|official|документ)", name):
            return f"Корпоративный вид при отправке с {ctx.sender_domain}"
    return None


@rule("missing_message_id", "Отсутствует Message-ID / Date", 12, "envelope",
      "Обязательные заголовки RFC отсутствуют — письмо сгенерировано скриптом.")
def r_missing_headers(ctx: MailContext) -> Optional[str]:
    missing = [h for h in ("message-id", "date", "mime-version") if not ctx.headers.get(h)]
    if len(missing) >= 2:
        return f"Нет обязательных заголовков: {', '.join(missing)}"
    return None


@rule("bulk_mailer", "Признаки массовой рассылки", 10, "envelope",
      "Заголовки массовых рассыльщиков и авто-ответчики.")
def r_bulk(ctx: MailContext) -> Optional[str]:
    auto = ctx.headers.get("auto-submitted", "")
    xmailer = ctx.headers.get("x-mailer", "").lower()
    if auto and auto.lower() not in ("no",):
        return f"Auto-Submitted: {auto}"
    if any(k in xmailer for k in ("php", "mass", "mailer", "sendblaster", "python")):
        return f"X-Mailer: {ctx.headers.get('x-mailer')}"
    return None


@rule("priority_urgent", "Искусственный высокий приоритет", 8, "social_engineering",
      "Письмо помечено наивысшим приоритетом без оснований.")
def r_priority(ctx: MailContext) -> Optional[str]:
    if ctx.headers.get("x-priority", "").strip() in ("1", "2"):
        return "X-Priority: 1/2 (высокий приоритет)"
    return None


# ------------------------------------------------------------
# ЛЕГИТИМНЫЕ ПРИЗНАКИ (СНИЖАЮТ РИСК)
# ------------------------------------------------------------
@rule("legit_unsubscribe", "Есть корректная отписка", -10, "legitimate",
      "Наличие List-Unsubscribe — признак легитимной рассылки.")
def r_unsub(ctx: MailContext) -> Optional[str]:
    if ctx.headers.get("list-unsubscribe"):
        return "Заголовок List-Unsubscribe присутствует"
    return None


@rule("legit_thread", "Продолжение переписки", -12, "legitimate",
      "Письмо является продолжением существующей темы (References/In-Reply-To).")
def r_thread(ctx: MailContext) -> Optional[str]:
    if ctx.headers.get("references") or ctx.headers.get("in-reply-to"):
        return "Письмо ссылается на предыдущие сообщения переписки"
    return None


@rule("legit_personal_name", "Персонализированное обращение", -8, "legitimate",
      "Отправитель знает имя получателя — нетипично для массового фишинга.")
def r_personal(ctx: MailContext) -> Optional[str]:
    if ctx.recipient_local and len(ctx.recipient_local) >= 4:
        name_part = re.split(r"[._\-0-9]", ctx.recipient_local)[0].lower()
        if name_part and name_part in ctx.full_text and not r_greeting(ctx):
            return f"В тексте используется имя получателя «{name_part}»"
    return None


# ============================================================
# ЗАПУСК
# ============================================================
def run_heuristics(ctx: MailContext) -> tuple[int, List[Evidence]]:
    evidence: List[Evidence] = []
    for r in RULES:
        try:
            detail = r.matcher(ctx)
        except Exception:  # правило не должно ронять анализ
            detail = None
        if detail:
            evidence.append(
                Evidence(
                    rule_id=r.id,
                    title=r.title,
                    points=r.points,
                    category=r.category,
                    detail=detail,
                )
            )
    total = sum(e.points for e in evidence)
    return max(0, min(100, total)), evidence


def rules_catalog() -> List[dict]:
    return [
        {
            "id": r.id,
            "title": r.title,
            "points": r.points,
            "category": r.category,
            "description": r.description,
        }
        for r in RULES
    ]
