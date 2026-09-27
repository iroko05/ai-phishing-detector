"""Тесты разбора заголовков аутентификации SPF/DKIM/DMARC (offline)."""
from __future__ import annotations

from app.analyzers.email_auth import evaluate_auth


def test_no_auth_headers_penalty():
    report = evaluate_auth({}, "evil.ru")
    assert report.score == 25
    assert report.spf == "unknown"


def test_all_pass_zero_score():
    headers = {
        "Authentication-Results":
            "mx.corp.ru; spf=pass smtp.mailfrom=corp.ru; "
            "dkim=pass header.d=corp.ru; dmarc=pass header.from=corp.ru",
    }
    report = evaluate_auth(headers, "corp.ru")
    assert report.spf == "pass"
    assert report.dkim == "pass"
    assert report.dmarc == "pass"
    assert report.score == 0


def test_spf_fail_heavy_penalty():
    headers = {
        "Authentication-Results":
            "mx.corp.ru; spf=fail smtp.mailfrom=evil.ru; dkim=none; dmarc=fail",
    }
    report = evaluate_auth(headers, "corp.ru")
    assert report.spf == "fail"
    assert report.dmarc == "fail"
    assert report.score >= 80


def test_received_spf_header_parsed():
    headers = {
        "Received-SPF": "fail (corp.ru: domain of x@evil.ru does not designate "
                        "1.2.3.4 as permitted sender)",
    }
    report = evaluate_auth(headers, "evil.ru")
    assert report.spf == "fail"


def test_worst_verdict_wins():
    headers = {
        "Authentication-Results":
            "mx1.corp.ru; spf=pass smtp.mailfrom=corp.ru\n"
            "mx2.corp.ru; spf=fail smtp.mailfrom=corp.ru; dkim=pass",
    }
    report = evaluate_auth(headers, "corp.ru")
    assert report.spf == "fail"


def test_dmarc_alignment_mismatch():
    headers = {
        "Authentication-Results":
            "mx.corp.ru; spf=pass smtp.mailfrom=other.ru; "
            "dkim=pass header.d=other.ru; dmarc=pass header.from=other.ru",
    }
    report = evaluate_auth(headers, "corp.ru")
    assert report.score >= 25
    assert any("alignment" in r.lower() or "совпадает" in r.lower()
               for r in report.reasons)


def test_softfail_moderate_penalty():
    headers = {
        "Authentication-Results":
            "mx.corp.ru; spf=softfail smtp.mailfrom=corp.ru; dkim=none; dmarc=none",
    }
    report = evaluate_auth(headers, "corp.ru")
    assert 40 <= report.score < 80
