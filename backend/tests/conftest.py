"""
Общие фикстуры тестов: полный офлайн (без сети) и временные каталоги.

Переменные окружения выставляются ДО импорта пакета ``app`` — конфигурация
(pydantic-settings) читается один раз при первом обращении, поэтому conftest
импортируется раньше тестовых модулей и глушит все внешние вызовы:

    * ANTISPAM_AI_ENABLED=false            — GigaChat не вызывается
    * ANTISPAM_RDAP_ENABLED=false          — возраст домена не проверяется
    * ANTISPAM_DNS_CHECK_ENABLED=false     — DNS не резолвится
    * ANTISPAM_FOLLOW_REDIRECTS=false      — редиректы не отслеживаются
    * ANTISPAM_MTA_MODE=disabled           — фоновые задачи не стартуют
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# --- офлайн-конфигурация: до первого импорта app -------------------------
# Присваиваем явно (не setdefault): набор тестов должен быть герметичным
# и не зависеть от переменных окружения, оставшихся в shell разработчика.
os.environ["ANTISPAM_API_KEYS"] = "test-api-key"
os.environ["ANTISPAM_ADMIN_TOKEN"] = "test-admin-token"
os.environ["ANTISPAM_MTA_TOKEN"] = "test-mta-token"
os.environ["ANTISPAM_AI_ENABLED"] = "false"
os.environ["ANTISPAM_RDAP_ENABLED"] = "false"
os.environ["ANTISPAM_DNS_CHECK_ENABLED"] = "false"
os.environ["ANTISPAM_FOLLOW_REDIRECTS"] = "false"
os.environ["ANTISPAM_MTA_MODE"] = "disabled"
os.environ["ANTISPAM_LOG_LEVEL"] = "WARNING"

# Временная БД и каталоги на сессию (не мусорим в рабочей копии)
_SESSION_TMP = tempfile.mkdtemp(prefix="antispam-tests-")
os.environ.setdefault("ANTISPAM_DB_PATH", str(Path(_SESSION_TMP) / "gateway.db"))
os.environ.setdefault("ANTISPAM_MTA_SPOOL_DIR", str(Path(_SESSION_TMP) / "spool"))
os.environ.setdefault("ANTISPAM_MTA_PROCESSED_DIR", str(Path(_SESSION_TMP) / "processed"))
os.environ.setdefault("ANTISPAM_MTA_QUARANTINE_DIR",
                      str(Path(_SESSION_TMP) / "quarantine-eml"))
os.environ.setdefault("ANTISPAM_QUARANTINE_DIR", str(Path(_SESSION_TMP) / "quarantine"))
os.environ.setdefault("ANTISPAM_AUDIT_LOG_PATH",
                      str(Path(_SESSION_TMP) / "audit" / "decisions.jsonl"))
os.environ.setdefault("ANTISPAM_ALLOWLIST_PATH",
                      str(Path(_SESSION_TMP) / "allowlist.json"))

# backend/ в sys.path, чтобы импортировались и main, и app
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.storage import db  # noqa: E402


@pytest.fixture()
def settings():
    """Единый синглтон настроек (тот же объект, что и в main.py)."""
    return get_settings()


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, settings, monkeypatch):
    """Каждый тест получает чистую БД во временном каталоге."""
    db_file = tmp_path / "gateway.db"
    monkeypatch.setattr(settings, "db_path", str(db_file))
    db.reset_state()
    db.init_db()

    # кэш списков конвейера живёт в синглтоне — сбрасываем между тестами,
    # иначе записи из БД предыдущего теста «протекают» в следующий
    from app.engine import pipeline as pipeline_module
    if pipeline_module._pipeline is not None:
        pipeline_module._pipeline.patterns.clear_cache()

    yield
    db.reset_state()


@pytest.fixture()
def api_headers():
    return {"X-API-Key": "test-api-key"}


@pytest.fixture()
def admin_headers(api_headers):
    return {**api_headers, "X-Admin-Token": "test-admin-token"}


@pytest.fixture()
def client():
    """TestClient REST-слоя (lifespan: инициализация БД, MTA выключен)."""
    from fastapi.testclient import TestClient

    import main

    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture()
def pipeline():
    from app.engine.pipeline import get_pipeline

    return get_pipeline()
