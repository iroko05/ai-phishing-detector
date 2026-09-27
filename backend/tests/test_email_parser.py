"""Тесты парсера сырых писем (.eml, RFC 5322) — offline."""
from __future__ import annotations

from app.analyzers.email_parser import authentication_context, extract_urls, parse_raw_email

SIMPLE_EML = """From: =?utf-8?B?0KHQu9GD0LbQsdCwINCx0LXQt9C+0L/QsNGB0L3QvtGB0YLQuCDQodCx0LXRgNCx0LDQvdC60LA=?= <security@sberbank-secure.top>
To: ivan.petrov@corp.ru
Subject: =?utf-8?B?0J/QvtC00YLQstC10YDQttC00LXQvdC40LUg0LrQvtC00LA=?=
Date: Sat, 26 Sep 2026 10:00:00 +0300
Message-ID: <123@evil.top>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Уважаемый сотрудник, срочно подтвердите пароль по ссылке
https://sberbank-secure.top/verify/login до конца дня, иначе аккаунт будет заблокирован!
"""

HTML_EML = """From: boss@corp-lookalike.ru
To: accounting@corp.ru
Subject: Счёт на оплату — срочно
Date: Sat, 26 Sep 2026 11:00:00 +0300
Message-ID: <456@evil.ru>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset=utf-8

Оплатите счёт, это конфиденциально, никому не сообщайте.

--BOUND
Content-Type: text/html; charset=utf-8

<html><body>
<a href="http://evil.ru/pay">https://bank.ru/pay</a>
<img src="http://tracker.evil.ru/pixel.gif">
</body></html>

--BOUND
Content-Type: application/zip; name="invoice.zip"
Content-Disposition: attachment; filename="invoice.zip"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAA==
--BOUND--
"""


def test_parse_simple_email():
    parsed = parse_raw_email(SIMPLE_EML)
    assert parsed["sender"] == "security@sberbank-secure.top"
    assert "Служба безопасности" in parsed["sender_display"]
    assert parsed["subject"] == "Подтверждение кода"
    assert "подтвердите" in parsed["text"].lower()
    assert parsed["message_id"] == "<123@evil.top>"
    assert "https://sberbank-secure.top/verify/login" in parsed["urls"]


def test_parse_multipart_html_and_attachment():
    parsed = parse_raw_email(HTML_EML)
    assert "конфиденциально" in parsed["text"]
    assert "evil.ru/pay" in parsed["html"]
    assert parsed["urls"], "ссылки должны быть извлечены из html"
    attachments = parsed["attachments"]
    assert any(a.filename == "invoice.zip" for a in attachments)
    zip_attachment = next(a for a in attachments if a.filename == "invoice.zip")
    assert zip_attachment.size > 0
    assert zip_attachment.content_type == "application/zip"


def test_extract_urls_dedup_and_cleanup():
    urls = extract_urls("Смотри https://a.ru/x, и https://a.ru/x.",
                        '<a href="https://b.ru/y">link</a>')
    assert urls == ["https://a.ru/x", "https://b.ru/y"]


def test_authentication_context_compiles():
    parsed = parse_raw_email(SIMPLE_EML)
    context = authentication_context(parsed)
    assert "reply-to" not in context  # отсутствующие заголовки не попадают в сводку


def test_recipient_hint_fallback():
    parsed = parse_raw_email("Subject: без получателя\n\nтело",
                             recipient_hint="hint@corp.ru")
    assert parsed["recipient"] == "hint@corp.ru"


def test_missing_headers_do_not_crash():
    parsed = parse_raw_email("Subject: пустое письмо\n\nтело")
    assert parsed["sender"] == ""
    assert parsed["text"] == "тело"
