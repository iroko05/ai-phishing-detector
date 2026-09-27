"""
Интеграция с почтовым шлюзом (MTA).

Два режима, оба без внешних зависимостей:

1. ``watch`` (по умолчанию) — «maildir-подобный» разбор каталога-спула.
   В ``mta_spool_dir`` падают письма ``*.eml`` (туда их кладет ``fetchmail``/
   ``getmail``/скрипт выгрузки из ящика). Каждое письмо разбирается конвейером:
     * verdict reject/quarantine → файл переносится в ``mta_quarantine_dir``
       и заводится запись в карантине;
     * иначе → ``mta_processed_dir`` (откуда его заберёт доvecot/MDA).
   Это ровно то, что делает фильтр-конвейер ``mail`` в Exim/Postfix, только
   отдельным процессом — легко поднять, легко отладить.

2. ``smtp`` — встроенный приёмный SMTP-сервер (минимальный, см. smtp_server.py).
   Шлюз отвечает ``550`` на отвергаемые письма, то есть они вообще не попадают
   в ящик получателя.

Режим ``disabled`` — только HTTP API.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from app.analyzers.email_parser import parse_raw_email
from app.config import get_settings
from app.storage.db import log_analysis, quarantine_save
from app.storage.stores import PatternStore

logger = logging.getLogger("gateway.mta")


class MtaWatcher:
    def __init__(self, pipeline: Any = None) -> None:
        self.settings = get_settings()
        self._pipeline = pipeline
        self._store = PatternStore()
        self._stop = asyncio.Event()
        self.processed = 0
        self.blocked = 0
        self.errors = 0
        self.last_scan: float = 0.0
        self.server: Any = None

    # ------------------------------------------------------------ доступ
    @property
    def pipeline(self):
        if self._pipeline is None:
            from app.engine.pipeline import get_pipeline

            self._pipeline = get_pipeline()
        return self._pipeline

    @pipeline.setter
    def pipeline(self, value: Any) -> None:
        self._pipeline = value

    @property
    def mode(self) -> str:
        return self.settings.mta_mode

    @property
    def stats(self) -> Dict[str, Any]:
        return {"mode": self.mode, "processed": self.processed,
                "blocked": self.blocked, "errors": self.errors,
                "last_scan": self.last_scan}

    def stop(self) -> None:
        self._stop.set()
        if self.server is not None:
            try:
                self.server.close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------ цикл
    async def run(self) -> None:
        mode = self.mode
        if mode == "disabled":
            logger.info("MTA-интеграция отключена (ANTISPAM_MTA_MODE=disabled)")
            return
        if mode == "smtp":
            await self._run_smtp()
            return
        await self._run_spool()

    async def _run_spool(self) -> None:
        spool = Path(self.settings.mta_spool_dir)
        spool.mkdir(parents=True, exist_ok=True)
        (Path(self.settings.mta_processed_dir)).mkdir(parents=True, exist_ok=True)
        (Path(self.settings.mta_quarantine_dir)).mkdir(parents=True, exist_ok=True)
        logger.info("наблюдаю за спулом %s (каждые %s с)",
                    spool, self.settings.mta_poll_seconds)
        while not self._stop.is_set():
            self.last_scan = time.time()
            try:
                await self.scan_once()
            except Exception:  # noqa: BLE001
                logger.exception("цикл спула")
            try:
                await asyncio.wait_for(self._stop.wait(),
                                       timeout=self.settings.mta_poll_seconds)
            except asyncio.TimeoutError:
                continue

    def _pending(self) -> List[Path]:
        spool = Path(self.settings.mta_spool_dir)
        if not spool.exists():
            return []
        files = [p for p in spool.iterdir()
                 if p.is_file() and p.suffix.lower() in (".eml", ".doc", ".txt", "")]
        return sorted(files, key=lambda p: p.stat().st_mtime)

    async def scan_once(self) -> int:
        handled = 0
        for path in self._pending():
            try:
                await self.process_file(path)
                handled += 1
            except Exception:  # noqa: BLE001
                self.errors += 1
                logger.exception("обработка %s", path)
        return handled

    # ------------------------------------------------------------ одно письмо
    async def process_file(self, path: Path) -> Dict[str, Any]:
        raw = path.read_bytes().decode("utf-8", errors="replace")
        verdict = await self.process_raw(raw, source="mta-spool")
        self._route(path, verdict.get("action", "deliver"))
        return verdict

    async def process_raw(self, raw: str, *, source: str = "mta") -> Dict[str, Any]:
        parsed = parse_raw_email(raw)
        result = await self.pipeline.analyze_raw(raw, source=source)
        try:
            result.id = log_analysis(result, source=source, api_key="mta")
        except Exception:  # noqa: BLE001
            logger.exception("журнал разбора")
        if result.action in ("reject", "quarantine", "block"):
            self.blocked += 1
            quarantine_save(
                analysis_id=result.id, score=result.risk_score, action=result.action,
                sender=parsed.get("sender", ""), subject=parsed.get("subject", ""),
                reason=result.decision_reason, raw_source=raw[:200_000],
                phishing_type=result.phishing_type,
            )
        self.processed += 1
        logger.info("MTA: %s → %s (%s баллов)", parsed.get("subject")
                    or parsed.get("sender"), result.action, result.risk_score)
        return {"action": result.action, "score": result.risk_score,
                "reason": result.decision_reason, "id": result.id}

    def _route(self, path: Path, action: str) -> None:
        target_dir = (Path(self.settings.mta_quarantine_dir)
                      if action in ("reject", "quarantine", "block")
                      else Path(self.settings.mta_processed_dir))
        target_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        destination = target_dir / f"{stamp}-{path.name}"
        counter = 1
        while destination.exists():
            destination = target_dir / f"{stamp}-{counter}-{path.name}"
            counter += 1
        shutil.move(str(path), str(destination))

    # ------------------------------------------------------------ smtp
    async def _run_smtp(self) -> None:
        from app.mta.smtp_server import SmtpFrontend

        async def handler(message: Dict[str, Any]) -> Dict[str, Any]:
            return await self.process_raw(message["data"], source="mta-smtp")

        server = SmtpFrontend(self.settings.mta_smtp_host, self.settings.mta_smtp_port,
                              handler, max_message_mb=self.settings.mta_max_message_mb)
        self.server = server
        await server.serve()


_watcher: Optional[MtaWatcher] = None


def get_watcher() -> MtaWatcher:
    global _watcher
    if _watcher is None:
        _watcher = MtaWatcher()
    return _watcher
