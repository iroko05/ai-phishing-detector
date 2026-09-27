"""
Разбор сырого письма (RFC 5322 / .eml) в нормализованный контекст анализа.

Извлекает: заголовки (включая цепочку Received и результаты аутентификации),
MIME-тему с кодировкой, text/html части, вложения (имя, размер, тип), ссылки
из текстовых и HTML-частей, а также домен отправителя из заголовка From.
"""
from __future__ import annotations

import email
import email.policy
import logging
import re
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

from app.schemas import AttachmentInfo

logger = logging.getLogger("gateway.parser")

URL_RE = re.compile(r"""(?:https?|ftp)://[^\s<>"'\)\]}]+""", re.I)
MAILTO_RE = re.compile(r"""mailto:([^\s<>"']+)""", re.I)
HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)
TRACK_RE = re.compile(r"""src\s*=\s*["']([^"']+)["']""", re.I)


def decode_mime_header(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def extract_urls(text: str, html: str = "") -> List[str]:
    urls: List[str] = []
    for source in (text or "", html or ""):
        if not source:
            continue
        for match in URL_RE.findall(source):
            cleaned = match.rstrip(".,;:!?'\"<>）)»» ")
            if cleaned and cleaned not in urls:
                urls.append(cleaned)
    # ссылки, зашитые в mailto/href без схемы
    if html:
        for match in HREF_RE.findall(html):
            if match.startswith(("http://", "https://")) and match not in urls:
                urls.append(match)
    return urls[:40]


def _decoded_content(part) -> str:
    """Текст части с фолбэком: письма без объявленного charset идут как ASCII
    и кириллица превращается в ``\ufffd`` — в этом случае декодируем как UTF-8."""
    try:
        content = part.get_content()
    except Exception:
        content = ""
    if isinstance(content, str) and "\ufffd" in content:
        payload = part.get_payload(decode=True) or b""
        if payload:
            try:
                content = payload.decode("utf-8", errors="replace")
            except Exception:
                pass
    return content if isinstance(content, str) else ""


def parse_raw_email(raw: str, recipient_hint: str = "") -> dict:
    """Возвращает нормализованное представление письма для анализаторов.

    ``recipient_hint`` — адрес получателя от MTA (если заголовок To отсутствует
    или не разбирается, используется как запасной вариант).

    Важно: письмо парсится из БАЙТОВ. При разборе из строки не-ASCII тело
    превращается в литеральные escape-последовательности (raw-unicode-escape),
    а разбор из байтов корректно декодирует тело по объявленному charset.
    """
    msg = message_from_bytes(raw.encode("utf-8", errors="replace"),
                             policy=email.policy.default)

    headers: Dict[str, str] = {}
    multi: Dict[str, List[str]] = {}
    for key in msg.keys():
        values = msg.get_all(key, [])
        decoded = decode_mime_header(", ".join(str(v) for v in values))
        headers[key.lower()] = decoded
        multi[key.lower()] = [decode_mime_header(str(v)) for v in values]

    real_from = headers.get("from", "")
    display_name, sender = parseaddr(real_from)
    display_name = decode_mime_header(display_name)

    to_addr = headers.get("to", "")
    _, recipient = parseaddr(to_addr)
    if not recipient and recipient_hint:
        recipient = recipient_hint

    text_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[AttachmentInfo] = []

    for part in msg.walk():
        content_type = (part.get_content_type() or "").lower()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        filename = decode_mime_header(filename) if filename else ""

        if disposition == "attachment" or (filename and content_type not in ("text/plain", "text/html")):
            payload = part.get_payload(decode=True) or b""
            attachments.append(AttachmentInfo(
                filename=filename or "unnamed",
                size=len(payload),
                content_type=content_type,
            ))
            continue

        if content_type == "text/plain":
            text_parts.append(_decoded_content(part))
        elif content_type == "text/html":
            html_parts.append(_decoded_content(part))

    text_body = "\n".join(p for p in text_parts if p).strip()
    html_body = "\n".join(html_parts).strip()

    # Вложения могут быть в виде вложенных message/rfc822
    if not attachments and msg.get_content_maintype() == "multipart":
        for part in msg.iter_attachments():
            payload = part.get_payload(decode=True) or b""
            attachments.append(AttachmentInfo(
                filename=decode_mime_header(part.get_filename()) or "unnamed",
                size=len(payload),
                content_type=(part.get_content_type() or ""),
            ))

    date_raw = headers.get("date", "")
    try:
        sent_at = parsedate_to_datetime(date_raw).isoformat() if date_raw else ""
    except Exception:
        sent_at = ""

    urls = extract_urls(text_body, html_body)
    # дополняем URL-объектами из тела письма, если они были «спрятаны» в HTML
    for match in re.findall(r"(?i)<a[^>]+href=[\"']([^\"']+)", html_body):
        if match.startswith(("http://", "https://")) and match not in urls:
            urls.append(match)

    return {
        "sender": sender or "",
        "sender_display": display_name or "",
        "recipient": recipient or "",
        "subject": decode_mime_header(headers.get("subject", "")),
        "text": text_body,
        "html": html_body,
        "urls": urls[:40],
        "attachments": attachments,
        "headers": headers,
        "headers_multi": multi,
        "message_id": headers.get("message-id", ""),
        "date": sent_at,
        "received_chain": multi.get("received", [])[:8],
    }


def authentication_context(parsed: dict) -> str:
    """Краткая сводка заголовков для передачи в ИИ-промпт как «данные шлюза»."""
    headers = parsed.get("headers", {}) or {}
    lines: List[str] = []
    for name in ("authentication-results", "received-spf", "dkim-signature",
                 "dmarc-result", "return-path", "reply-to", "sender", "x-originating-ip",
                 "received"):
        values = (parsed.get("headers_multi") or {}).get(name) or []
        if not values and headers.get(name):
            values = [headers[name]]
        for value in values[:3]:
            lines.append(f"{name}: {value[:220]}")
    return "\n".join(lines[:12])