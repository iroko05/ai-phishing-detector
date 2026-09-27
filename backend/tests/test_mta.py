"""Тесты MTA-интеграции: наблюдатель спула и приёмный SMTP-фронт (offline)."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from app.engine.pipeline import get_pipeline
from app.mta.smtp_server import SmtpFrontend
from app.mta.watcher import MtaWatcher
from app.storage import db

PHISHING_EML = """From: security@sberbank-secure.top
To: ivan.petrov@corp.ru
Subject: =?utf-8?B?0JHRgNC+0L7QtNC10YfQuNC1INC60LDQuiDQu9C+0LvQuA==?=
Date: Sat, 26 Sep 2026 10:00:00 +0300
Message-ID: <phish-1@evil.top>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Уважаемый сотрудник, срочно сообщите пароль и код из SMS
по ссылке https://sberbank-secure.top/verify/login,
иначе аккаунт будет заблокирован. Это конфиденциально, никому не сообщайте.
"""

CLEAN_EML = """From: hr@corp.ru
To: team@corp.ru
Subject: Напоминание о встрече
Date: Sat, 26 Sep 2026 12:00:00 +0300
Message-ID: <clean-1@corp.ru>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Коллеги, напоминаю о планёрке в понедельник в 10:00.
"""


def make_watcher(tmp_path: Path, settings, monkeypatch) -> MtaWatcher:
    """Наблюдатель с каталогами спула во временной папке."""
    spool = tmp_path / "spool"
    processed = tmp_path / "processed"
    quarantine = tmp_path / "quarantine-eml"
    for directory in (spool, processed, quarantine):
        directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "mta_mode", "watch")
    monkeypatch.setattr(settings, "mta_spool_dir", str(spool))
    monkeypatch.setattr(settings, "mta_processed_dir", str(processed))
    monkeypatch.setattr(settings, "mta_quarantine_dir", str(quarantine))
    return MtaWatcher(pipeline=get_pipeline())


# ---------------------------------------------------------------- спул
def test_spool_watcher_routes_phishing_to_quarantine(tmp_path, settings, monkeypatch):
    watcher = make_watcher(tmp_path, settings, monkeypatch)
    spool = Path(settings.mta_spool_dir)
    (spool / "phish.eml").write_text(PHISHING_EML, encoding="utf-8")

    handled = asyncio.run(watcher.scan_once())

    assert handled == 1
    assert watcher.processed == 1
    assert watcher.blocked == 1
    assert not (spool / "phish.eml").exists(), "файл должен покинуть спул"
    quarantined = list(Path(settings.mta_quarantine_dir).iterdir())
    assert len(quarantined) == 1
    assert "phish.eml" in quarantined[0].name

    # запись в карантине БД появилась
    items = db.quarantine_list(status="pending")
    assert len(items) == 1
    assert items[0]["score"] >= 55


def test_spool_watcher_routes_clean_to_processed(tmp_path, settings, monkeypatch):
    watcher = make_watcher(tmp_path, settings, monkeypatch)
    spool = Path(settings.mta_spool_dir)
    (spool / "clean.eml").write_text(CLEAN_EML, encoding="utf-8")

    asyncio.run(watcher.scan_once())

    processed = list(Path(settings.mta_processed_dir).iterdir())
    assert len(processed) == 1
    assert "clean.eml" in processed[0].name
    assert list(Path(settings.mta_quarantine_dir).iterdir()) == []
    assert watcher.blocked == 0
    # вердикт попал в журнал разборов
    assert db.stats_overall()["total"] == 1


def test_spool_watcher_ignores_foreign_extensions(tmp_path, settings, monkeypatch):
    watcher = make_watcher(tmp_path, settings, monkeypatch)
    (Path(settings.mta_spool_dir) / "image.png").write_bytes(b"\x89PNG")
    assert asyncio.run(watcher.scan_once()) == 0
    assert (Path(settings.mta_spool_dir) / "image.png").exists()


def test_spool_watcher_stats(tmp_path, settings, monkeypatch):
    watcher = make_watcher(tmp_path, settings, monkeypatch)
    stats = watcher.stats
    assert stats["mode"] == "watch"
    assert stats["processed"] == 0


# ---------------------------------------------------------------- SMTP
async def _read_reply(reader: asyncio.StreamReader) -> str:
    """Читает (возможно многострочный) SMTP-ответ до строки с пробелом после кода."""
    lines: list[str] = []
    while True:
        raw = (await reader.readline()).decode().strip()
        lines.append(raw)
        # «250-продолжение» против «250 конец»
        if len(raw) < 4 or raw[3] == " ":
            return "\n".join(lines)


async def _smtp_session(mail_from: str, rcpt_to: str, eml: str,
                        handler) -> str:
    """Прогоняет письмо через SMTP-фронт и возвращает финальный ответ на '.'."""
    server = SmtpFrontend("127.0.0.1", 0, handler)
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(50):
            if server._server is not None:
                break
            await asyncio.sleep(0.02)

        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)

        async def command(line: str) -> str:
            writer.write((line + "\r\n").encode())
            await writer.drain()
            return await _read_reply(reader)

        assert (await _read_reply(reader)).startswith("220")
        assert (await command("EHLO test.local")).startswith("250")
        assert (await command(f"MAIL FROM:<{mail_from}>")).startswith("250")
        assert (await command(f"RCPT TO:<{rcpt_to}>")).startswith("250")
        assert (await command("DATA")).startswith("354")

        # тело письма уходит одним блоком, точка завершает передачу
        writer.write((eml + "\r\n.\r\n").encode())
        await writer.drain()
        final = await _read_reply(reader)

        writer.write(b"QUIT\r\n")
        await writer.drain()
        writer.close()
        return final
    finally:
        server.close()
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass


def test_smtp_frontend_rejects_phishing(settings):
    async def handler(message):
        watcher = MtaWatcher(pipeline=get_pipeline())
        return await watcher.process_raw(message["data"], source="mta-smtp")

    final_reply = asyncio.run(_smtp_session(
        "security@sberbank-secure.top", "ivan.petrov@corp.ru",
        PHISHING_EML, handler))
    assert final_reply.startswith("550"), "фишинговое письмо должно получить 550"


def test_smtp_frontend_accepts_clean(settings):
    async def handler(message):
        return {"action": "deliver", "score": 5, "reason": "clean"}

    final_reply = asyncio.run(_smtp_session(
        "hr@corp.ru", "team@corp.ru", CLEAN_EML, handler))
    assert final_reply.startswith("250"), "чистое письмо должно быть принято"


def test_smtp_frontend_counters(settings):
    async def handler(message):
        return {"action": "deliver", "score": 0, "reason": "ok"}

    async def scenario() -> None:
        server = SmtpFrontend("127.0.0.1", 0, handler)
        task = asyncio.create_task(server.serve())
        try:
            for _ in range(50):
                if server._server is not None:
                    break
                await asyncio.sleep(0.02)
            assert server.accepted == 0 and server.rejected == 0
        finally:
            server.close()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    asyncio.run(scenario())
