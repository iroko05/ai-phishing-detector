"""Тесты анализа ссылок (полностью offline: RDAP/DNS/редиректы выключены)."""
from __future__ import annotations

from app.analyzers.url_intel import UrlIntel
from app.config import get_settings


def make_intel() -> UrlIntel:
    return UrlIntel(settings=get_settings())


def test_clean_url_low_score():
    report, verdicts = make_intel().analyze(["https://www.wikipedia.org/wiki/Phishing"])
    assert report.score < 20
    assert verdicts[0].suspicious is False


def test_ip_host_url_is_suspicious():
    report, verdicts = make_intel().analyze(["http://192.168.10.25/verify/account"])
    assert verdicts[0].suspicious is True
    assert verdicts[0].score >= 40
    assert report.score >= 40


def test_brand_in_foreign_domain():
    report, verdicts = make_intel().analyze(
        ["https://sberbank-secure-login.verify-account.top/auth"])
    reasons = " ".join(verdicts[0].reasons).lower()
    assert "бренд" in reasons or "тайпосквот" in reasons
    assert verdicts[0].suspicious is True
    assert report.score >= 35


def test_typosquatting_of_official_domain():
    report, verdicts = make_intel().analyze(["https://sberbankk.ru/login"])
    reasons = " ".join(verdicts[0].reasons).lower()
    assert "тайпосквот" in reasons
    assert verdicts[0].suspicious is True


def test_official_brand_domain_is_clean():
    report, verdicts = make_intel().analyze(["https://sberbank.ru/person/payments"])
    assert verdicts[0].suspicious is False
    assert verdicts[0].score == 0


def test_shortener_flagged():
    report, verdicts = make_intel().analyze(["https://bit.ly/3xYz12"])
    reasons = " ".join(verdicts[0].reasons).lower()
    assert "сокращател" in reasons
    assert verdicts[0].suspicious is True


def test_open_redirect_param_flagged():
    report, verdicts = make_intel().analyze(
        ["https://corp.example.com/redirect?url=http://evil.ru/steal"])
    reasons = " ".join(verdicts[0].reasons).lower()
    assert "open-redirect" in reasons


def test_suspicious_tld_and_auth_path():
    report, verdicts = make_intel().analyze(
        ["https://secure-login-account.verify.click/confirm/password"])
    assert verdicts[0].suspicious is True
    assert report.score >= 30


def test_punycode_idn_flagged():
    report, verdicts = make_intel().analyze(["https://xn--80ak6aa92e.ru/login"])
    reasons = " ".join(verdicts[0].reasons).lower()
    assert "punycode" in reasons or "idn" in reasons


def test_userinfo_masking_flagged():
    report, verdicts = make_intel().analyze(
        ["https://sberbank.ru@evil-host.top/login"])
    reasons = " ".join(verdicts[0].reasons).lower()
    assert "@" in " ".join(verdicts[0].reasons) or "маскировк" in reasons


def test_many_domains_in_one_letter():
    urls = [f"https://site{i}.example{i}.top/login" for i in range(5)]
    report, verdicts = make_intel().analyze(urls)
    rule_ids = {e.rule_id for e in report.evidence}
    assert "url_many_domains" in rule_ids


def test_empty_input_skipped():
    report, verdicts = make_intel().analyze([])
    assert report.status == "skipped"
    assert verdicts == []
    assert report.score == 0


def test_registrable_domain_helper():
    intel = make_intel()
    assert intel._registrable_domain("a.b.sberbank.ru") == "sberbank.ru"
    assert intel._registrable_domain("shop.example.com.ru") == "example.com.ru"
    assert intel._registrable_domain("example.com") == "example.com"


def test_levenshtein_typosquat_detector():
    intel = make_intel()
    assert intel._looks_like_typosquat("sberbank.ru", "sberbankk.ru") is True
    assert intel._looks_like_typosquat("sberbank.ru", "sberbank.ru") is False
    assert intel._looks_like_typosquat("sberbank.ru", "wildberries.ru") is False
