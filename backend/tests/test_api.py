"""Тесты REST-слоя (main.py) через TestClient — без сети."""
from __future__ import annotations

PHISHING = {
    "sender": "security@sberbank-secure.top",
    "recipient": "ivan.petrov@corp.ru",
    "subject": "Срочно: подтвердите данные аккаунта",
    "body": "Уважаемый сотрудник! Немедленно подтвердите ваш пароль по ссылке "
            "https://sberbank-secure.top/verify/login, иначе аккаунт будет "
            "заблокирован в течение часа.",
    "urls": ["https://sberbank-secure.top/verify/login"],
}

CLEAN = {
    "sender": "hr@corp.ru",
    "recipient": "ivan.petrov@corp.ru",
    "subject": "Поздравляем с юбилеем",
    "body": "Иван, поздравляем с десятилетием работы в компании!",
}

RAW_EML = """From: security@sberbank-secure.top
To: ivan.petrov@corp.ru
Subject: =?utf-8?B?0J/QvtC00YLQstC10YDQttC00LXQvdC40LUg0LrQvtC00LA=?=
Date: Sat, 26 Sep 2026 10:00:00 +0300
Message-ID: <789@evil.top>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Уважаемый сотрудник, срочно сообщите код из SMS и пароль,
иначе доступ будет заблокирован. Это конфиденциально, никому не сообщайте.
"""


# ---------------------------------------------------------------- health
def test_health_open_without_key(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["ai_configured"] is False
    assert body["mta"]["mode"] == "disabled"


# ---------------------------------------------------------------- auth
def test_api_requires_key(client):
    assert client.post("/api/v1/gateway/intercept", json=PHISHING).status_code == 401


def test_wrong_key_rejected(client):
    response = client.post("/api/v1/gateway/intercept",
                           headers={"X-API-Key": "nope"}, json=PHISHING)
    assert response.status_code == 401


def test_mta_verify_accepts_mta_token(client):
    response = client.post("/api/v1/gateway/mta-verify",
                           headers={"X-MTA-Token": "test-mta-token"},
                           json={"sender": "a@b.ru", "recipient": "c@d.ru",
                                 "subject": "s", "body": "обычное письмо"})
    assert response.status_code == 200
    assert response.json()["action"] == "accept"


# ---------------------------------------------------------------- анализ
def test_intercept_phishing_letter(client, api_headers):
    response = client.post("/api/v1/gateway/intercept",
                           headers=api_headers, json=PHISHING)
    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] >= 55
    assert body["action"] in ("quarantine", "block", "hold")
    assert body["phishing_type"] in ("credential_harvest", "brand_impersonation",
                                     "suspicious")
    assert body["id"] is not None
    signals = {s["rule_id"] for s in body["signals"]}
    assert "credential_harvest" in signals
    assert body["modules_status"]["ai"] in ("not_configured", "skipped")


def test_intercept_clean_letter_delivered(client, api_headers):
    response = client.post("/api/v1/gateway/intercept",
                           headers=api_headers, json=CLEAN)
    assert response.status_code == 200
    body = response.json()
    assert body["action"] in ("allow", "warn")
    assert body["risk_score"] < 55


def test_intercept_empty_body_rejected(client, api_headers):
    payload = {**CLEAN, "body": "   "}
    assert client.post("/api/v1/gateway/intercept",
                       headers=api_headers, json=payload).status_code == 400


def test_analyze_raw_eml(client, api_headers):
    response = client.post("/api/v1/gateway/analyze/raw",
                           headers=api_headers,
                           json={"raw_email": RAW_EML, "recipient": "ivan@corp.ru"})
    assert response.status_code == 200
    body = response.json()
    assert body["sender"] == "security@sberbank-secure.top"
    assert body["risk_score"] >= 55
    assert body["action"] in ("hold", "quarantine", "block")


def test_analyze_raw_empty_rejected(client, api_headers):
    response = client.post("/api/v1/gateway/analyze/raw",
                           headers=api_headers, json={"raw_email": "  "})
    assert response.status_code == 400


def test_mta_verify_verdicts(client, api_headers):
    phishing = client.post("/api/v1/gateway/mta-verify", headers=api_headers,
                           json=PHISHING)
    assert phishing.status_code == 200
    assert phishing.json()["action"] in ("quarantine", "reject")

    clean = client.post("/api/v1/gateway/mta-verify", headers=api_headers, json=CLEAN)
    assert clean.json()["action"] == "accept"


# ---------------------------------------------------------------- журнал и статистика
def test_stats_after_analysis(client, api_headers):
    client.post("/api/v1/gateway/intercept", headers=api_headers, json=PHISHING)
    client.post("/api/v1/gateway/intercept", headers=api_headers, json=CLEAN)
    response = client.get("/api/v1/stats", headers=api_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["overview"]["total"] == 2
    assert body["overview"]["avg_score"] > 0
    assert isinstance(body["hourly"], list)


def test_logs_and_details(client, api_headers):
    created = client.post("/api/v1/gateway/intercept",
                          headers=api_headers, json=PHISHING).json()
    logs = client.get("/api/v1/logs", headers=api_headers).json()
    assert len(logs) == 1
    assert logs[0]["id"] == created["id"]

    details = client.get(f"/api/v1/logs/{created['id']}", headers=api_headers)
    assert details.status_code == 200
    payload = details.json()["payload"]
    assert payload["signals"]

    missing = client.get("/api/v1/logs/999999", headers=api_headers)
    assert missing.status_code == 404


def test_sender_history(client, api_headers):
    client.post("/api/v1/gateway/intercept", headers=api_headers, json=PHISHING)
    response = client.get("/api/v1/sender/sberbank-secure.top", headers=api_headers)
    assert response.status_code == 200
    assert response.json()["total"] == 1


# ---------------------------------------------------------------- карантин
def test_quarantine_flow(client, api_headers, admin_headers):
    created = client.post("/api/v1/gateway/intercept",
                          headers=api_headers, json=PHISHING).json()
    assert created["action"] in ("quarantine", "block", "hold")

    items = client.get("/api/v1/quarantine", headers=api_headers).json()["items"]
    assert len(items) == 1
    record_id = items[0]["id"]

    # выпуск из карантина требует админ-токен
    forbidden = client.post(f"/api/v1/quarantine/{record_id}/release",
                            headers=api_headers)
    assert forbidden.status_code == 403

    released = client.post(f"/api/v1/quarantine/{record_id}/release",
                           headers=admin_headers, params={"note": "ложное срабатывание"})
    assert released.status_code == 200
    assert released.json()["status"] == "released"

    # повторная обработка уже обработанной записи невозможна
    again = client.post(f"/api/v1/quarantine/{record_id}/release",
                        headers=admin_headers)
    assert again.status_code == 409


def test_quarantine_item_details(client, api_headers):
    client.post("/api/v1/gateway/intercept", headers=api_headers, json=PHISHING)
    items = client.get("/api/v1/quarantine", headers=api_headers).json()["items"]
    detail = client.get(f"/api/v1/quarantine/{items[0]['id']}", headers=api_headers)
    assert detail.status_code == 200
    assert "raw_source" in detail.json()


# ---------------------------------------------------------------- списки
def test_lists_crud_and_pipeline_effect(client, api_headers, admin_headers):
    # без админ-токена добавление запрещено
    assert client.post("/api/v1/lists", headers=api_headers,
                       params={"pattern": "corp.ru"}).status_code == 403

    added = client.post("/api/v1/lists", headers=admin_headers,
                        params={"pattern": "corp.ru", "kind": "allow",
                                "note": "наш домен"})
    assert added.status_code == 200
    record_id = added.json()["id"]

    listing = client.get("/api/v1/lists", headers=api_headers,
                         params={"kind": "allow"}).json()
    assert any(row["pattern"] == "corp.ru" for row in listing)

    # письмо из белого списка доставляется без ограничений
    verdict = client.post("/api/v1/gateway/intercept", headers=api_headers,
                          json={**CLEAN, "sender": "boss@corp.ru"}).json()
    assert verdict["action"] == "allow"
    assert verdict["allowlisted"] is True

    removed = client.delete(f"/api/v1/lists/{record_id}", headers=admin_headers)
    assert removed.status_code == 200
    assert client.delete(f"/api/v1/lists/{record_id}",
                         headers=admin_headers).status_code == 404


def test_denylist_blocks(client, api_headers, admin_headers):
    client.post("/api/v1/lists", headers=admin_headers,
                params={"pattern": "evil-spammer.top", "kind": "deny"})
    verdict = client.post("/api/v1/gateway/intercept", headers=api_headers, json={
        "sender": "spam@evil-spammer.top", "recipient": "ivan@corp.ru",
        "subject": "выигрыш", "body": "Вы выиграли! Заберите приз немедленно!",
    }).json()
    assert verdict["action"] == "block"
    assert verdict["risk_score"] >= 85


# ---------------------------------------------------------------- прочее
def test_config_masks_secrets(client, api_headers):
    body = client.get("/api/v1/config", headers=api_headers).json()
    assert body["api_keys"] == "***"
    assert body["admin_token"] == "***"


def test_rate_limit_kicks_in(client, api_headers, settings):
    original = settings.rate_limit_per_ip
    settings.rate_limit_per_ip = 3
    try:
        codes = [client.get("/api/v1/logs", headers=api_headers).status_code
                 for _ in range(6)]
        assert 429 in codes
    finally:
        settings.rate_limit_per_ip = original
        from main import _rate_buckets
        _rate_buckets.clear()
