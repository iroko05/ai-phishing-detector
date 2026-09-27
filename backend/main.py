"""
AI-Phishing Gateway — REST-слой над пакетом ``app``.

Здесь только транспорт: приём HTTP-запросов, аутентификация, лимиты частоты,
CORS и жизненный цикл сервиса. Вся бизнес-логика живёт в пакете ``app``:

    app.engine.pipeline   — конвейер анализа письма
    app.engine.scoring    — взвешенный движок решения
    app.mta.watcher       — SMTP-фронт и наблюдатель за спулом
    app.storage.db        — журнал разборов, карантин, списки, статистика
    app.security          — ключи доступа и журнал действий

Endpoints:
    GET  /health                                   — состояние шлюза (без ключа)
    POST /api/v1/gateway/intercept                 — анализ структурированного письма
    POST /api/v1/gateway/analyze/raw               — анализ сырого письма (.eml)
    POST /api/v1/gateway/mta-verify                — вердикт для MTA (accept/tag/quarantine/reject)
    GET  /api/v1/stats, /api/v1/logs, /api/v1/logs/{id} — статистика и журнал
    GET  /api/v1/quarantine, POST .../{id}/release|reject — карантин (админ)
    GET/POST/DELETE /api/v1/lists                  — белые/чёрные списки (админ)
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.engine.pipeline import get_pipeline
from app.logging_setup import setup_logging
from app.mta.watcher import MtaWatcher, get_watcher
from app.schemas import (
    AnalysisResult,
    EmailInput,
    IncomingEmail,
    MtaEmailInput,
    MtaResponse,
    RawEmailInput,
)
from app.security.audit import audit
from app.security.keys import check_admin_token, check_api_key
from app.storage import db

settings = get_settings()
setup_logging(settings.log_level, settings.log_json)
logger = logging.getLogger("gateway.api")

# ============================================================
# ЖИЗНЕННЫЙ ЦИКЛ: БД + MTA-интеграция (SMTP-фронт / наблюдатель спула)
# ============================================================
_watcher: Optional[MtaWatcher] = None
_mta_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    global _watcher, _mta_task
    settings.ensure_dirs()
    db.init_db()
    audit.log("gateway_started", detail=f"mta_mode={settings.mta_mode}")

    if settings.mta_mode != "disabled":
        _watcher = get_watcher()
        _mta_task = asyncio.create_task(_watcher.run(), name="mta-watcher")
        logger.info("MTA-интеграция запущена в режиме %s", settings.mta_mode)
    else:
        logger.info("MTA-интеграция отключена (ANTISPAM_MTA_MODE=disabled)")

    try:
        yield
    finally:
        if _watcher is not None:
            _watcher.stop()
        if _mta_task is not None and not _mta_task.done():
            _mta_task.cancel()
            try:
                await _mta_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        audit.log("gateway_stopped")


app = FastAPI(
    title=settings.app_name,
    description="Шлюз анализа корпоративной почты на фишинг, BEC и социальную инженерию",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# ============================================================
# ОГРАНИЧЕНИЕ ЧАСТОТЫ ЗАПРОСОВ (скользящее окно в памяти)
# ============================================================
_rate_buckets: Dict[str, deque] = defaultdict(deque)
_rate_lock = asyncio.Lock()


async def _rate_limit_exceeded(ip: str) -> bool:
    limit, window = settings.rate_limit_per_ip, settings.rate_limit_window
    now = time.time()
    async with _rate_lock:
        bucket = _rate_buckets[ip]
        while bucket and bucket[0] < now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            return True
        bucket.append(now)
        return False


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):  # type: ignore[name-defined]
    client_ip = (request.client.host if request.client else "") or "unknown"
    if request.url.path.startswith("/api/") and await _rate_limit_exceeded(client_ip):
        audit.log("rate_limited", actor=client_ip, target=request.url.path,
                  ok=False, ip=client_ip)
        return JSONResponse(status_code=429, content={"detail": "Слишком много запросов"})
    return await call_next(request)


# ============================================================
# АУТЕНТИФИКАЦИЯ
# ============================================================
async def require_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    """Пустой ANTISPAM_API_KEYS = доступ закрыт (безопасный дефолт)."""
    if not check_api_key(x_api_key, settings.key_list):
        audit.log("auth_failed", actor=x_api_key or "", detail="REST API", ok=False)
        raise HTTPException(status_code=401, detail="Требуется корректный X-API-Key")
    return x_api_key or ""


async def require_mta_access(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    x_mta_token: Optional[str] = Header(default=None, alias="X-MTA-Token"),
) -> str:
    """MTA-эндпоинт: подходит API-ключ или общий секрет SMTP-фронта."""
    if check_api_key(x_api_key, settings.key_list):
        return x_api_key or ""
    if settings.mta_token and check_api_key(x_mta_token, [settings.mta_token]):
        return "mta"
    audit.log("auth_failed", actor=x_api_key or "", detail="mta-verify", ok=False)
    raise HTTPException(status_code=401,
                        detail="Требуется X-API-Key или X-MTA-Token")


async def require_admin_token(
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
    api_key: str = Depends(require_api_key),
) -> str:
    if not check_admin_token(x_admin_token, settings.admin_token):
        audit.log("auth_failed", actor=api_key, detail="admin operation", ok=False)
        raise HTTPException(status_code=403, detail="Требуется корректный X-Admin-Token")
    return api_key


# ============================================================
# ЗДОРОВЬЕ
# ============================================================
@app.get("/health")
def health() -> Dict[str, Any]:
    db_ok = True
    try:
        db.stats_overall()
    except Exception:  # noqa: BLE001
        logger.exception("health check: БД недоступна")
        db_ok = False
    watcher_stats = _watcher.stats if _watcher is not None else {"mode": "disabled"}
    return {
        "status": "ok" if db_ok else "degraded",
        "version": app.version,
        "ai_configured": settings.ai_configured,
        "mta": watcher_stats,
        "database": "ok" if db_ok else "error",
    }


# ============================================================
# АНАЛИЗ ПИСЕМ
# ============================================================
async def _log_and_quarantine(result: AnalysisResult, raw_source: str,
                              source: str, api_key: str) -> AnalysisResult:
    """Сохраняет вердикт в журнал; при негативном решении — в карантин."""
    try:
        result.id = db.log_analysis(result, source=source, api_key=api_key)
    except Exception:  # noqa: BLE001
        logger.exception("не удалось сохранить разбор в журнал")
    if result.action in ("quarantine", "block"):
        try:
            db.quarantine_save(
                analysis_id=result.id, score=result.risk_score, action=result.action,
                sender=result.sender, subject=result.subject,
                recipient=result.recipient, reason=result.decision_reason,
                raw_source=raw_source[: settings.max_email_size],
                phishing_type=result.phishing_type,
            )
        except Exception:  # noqa: BLE001
            logger.exception("не удалось поставить письмо в карантин")
    return result


@app.post("/api/v1/gateway/intercept", response_model=AnalysisResult)
async def intercept_email(
    email: IncomingEmail,
    api_key: str = Depends(require_api_key),
) -> AnalysisResult:
    """Анализ структурированного письма: поля sender/recipient/subject/body/urls."""
    if not email.body.strip() and not email.html_body.strip():
        raise HTTPException(status_code=400, detail="Тело письма не может быть пустым")
    pipeline = get_pipeline()
    result = await pipeline.analyze_email(email, source="api")
    return await _log_and_quarantine(result, email.body or email.html_body,
                                     "api", api_key)


@app.post("/api/v1/gateway/analyze/raw", response_model=AnalysisResult)
async def analyze_raw_email(
    payload: RawEmailInput,
    api_key: str = Depends(require_api_key),
) -> AnalysisResult:
    """Разбор сырого письма RFC 5322 (.eml) и полный конвейер анализа."""
    if not payload.raw_email.strip():
        raise HTTPException(status_code=400, detail="Письмо не может быть пустым")
    if len(payload.raw_email) > settings.max_email_size:
        raise HTTPException(status_code=413, detail="Письмо слишком большое")
    pipeline = get_pipeline()
    result = await pipeline.analyze_raw(payload.raw_email, payload.recipient,
                                        source="eml")
    return await _log_and_quarantine(result, payload.raw_email, "eml", api_key)


_MTA_ACTION = {
    "allow": "accept",
    "warn": "tag",
    "hold": "quarantine",
    "quarantine": "quarantine",
    "block": "reject",
}


@app.post("/api/v1/gateway/mta-verify", response_model=MtaResponse)
async def mta_verify_email(
    email: MtaEmailInput,
    _key: str = Depends(require_mta_access),
) -> MtaResponse:
    """Вердикт для MTA: accept / tag / quarantine / reject."""
    if not email.body.strip():
        raise HTTPException(status_code=400, detail="Тело письма не может быть пустым")
    pipeline = get_pipeline()
    parsed = EmailInput(
        sender=email.sender, recipient=email.recipient, subject=email.subject,
        body=email.body, headers=email.headers, attachments=email.attachments,
    )
    result = await pipeline.analyze_email(parsed, source="mta-api")

    action = _MTA_ACTION.get(result.action, "accept")
    add_headers: Dict[str, str] = {
        "X-Phishing-Score": str(result.risk_score),
        "X-Phishing-Action": action,
        "X-Phishing-Type": result.phishing_type,
    }
    if action == "tag":
        add_headers["Subject"] = f"[ПОДОЗРИТЕЛЬНО {result.risk_score}%] {result.subject}"

    message = {
        "accept": "OK",
        "tag": f"Suspicious content, score {result.risk_score}/100",
        "quarantine": f"Quarantined: {result.phishing_type or 'suspicious'}",
        "reject": f"Rejected by security gateway (score {result.risk_score})",
    }[action]

    return MtaResponse(
        action=action,
        risk_score=result.risk_score,
        message=message,
        add_headers=add_headers,
        heuristics_report=result.heuristics_report,
        url_analysis=result.url_analysis,
        auth_report=result.auth_report,
        ai_report=result.ai_report,
        text_report=result.text_report,
        attachment_report=result.attachment_report,
        phishing_type=result.phishing_type,
        targeted=result.targeted,
        signals=result.signals,
    )


# ============================================================
# СТАТИСТИКА И ЖУРНАЛ РАЗБОРОВ
# ============================================================
@app.get("/api/v1/stats")
def stats(days: int = Query(default=7, ge=1, le=90),
          _: str = Depends(require_api_key)) -> Dict[str, Any]:
    since = db.since_iso(days)
    return {
        "overview": db.stats_overall(),
        "period_days": days,
        "by_action": db.stats_by_action(since),
        "by_type": db.stats_by_type(since),
        "daily": db.stats_daily(days),
        "hourly": db.stats_hourly(24),
        "top_senders": db.top_senders(since),
        "top_rules": db.top_rules(days),
        "top_urls": db.top_urls(days),
        "quarantine": db.quarantine_stats(),
        "audit": db.audit_stats(days=days),
        "mta_last_seen": db.mta_last_seen(),
        "ai_stats": get_pipeline().ai.stats,
    }


@app.get("/api/v1/logs")
def logs(limit: int = Query(default=50, le=500),
         action: Optional[str] = None,
         min_score: int = 0,
         _: str = Depends(require_api_key)) -> List[Dict[str, Any]]:
    return db.recent_logs(limit=limit, action=action, min_score=min_score)


@app.get("/api/v1/logs/{analysis_id}")
def log_details(analysis_id: int, _: str = Depends(require_api_key)) -> Dict[str, Any]:
    item = db.get_analysis(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Разбор не найден")
    return item


@app.get("/api/v1/sender/{domain}")
def sender_history(domain: str,
                   days: int = Query(default=30, le=365),
                   _: str = Depends(require_api_key)) -> Dict[str, Any]:
    return db.sender_history(domain, days=days)


# ============================================================
# КАРАНТИН
# ============================================================
@app.get("/api/v1/quarantine")
def quarantine_list(status: str = "pending",
                    limit: int = Query(default=50, le=200),
                    offset: int = 0,
                    _: str = Depends(require_api_key)) -> Dict[str, Any]:
    return {
        "items": db.quarantine_list(status=None if status == "all" else status,
                                    limit=limit, offset=offset),
        "stats": db.quarantine_stats(),
    }


@app.get("/api/v1/quarantine/{record_id}")
def quarantine_item(record_id: int, _: str = Depends(require_api_key)) -> Dict[str, Any]:
    item = db.quarantine_get(record_id)
    if not item:
        raise HTTPException(status_code=404, detail="Запись карантина не найдена")
    return item


@app.post("/api/v1/quarantine/{record_id}/{action}")
def quarantine_handle(
    record_id: int,
    action: str,
    note: str = "",
    api_key: str = Depends(require_admin_token),
) -> Dict[str, Any]:
    if action not in ("release", "reject"):
        raise HTTPException(status_code=400, detail="action должен быть release или reject")
    if not db.quarantine_update(record_id, action, operator=api_key, note=note):
        raise HTTPException(status_code=409, detail="Запись не найдена или уже обработана")
    audit.log(f"quarantine_{action}", actor=api_key, target=str(record_id),
              detail=note[:200])
    return {"id": record_id, "status": "released" if action == "release" else "rejected"}


# ============================================================
# СПИСКИ ОТПРАВИТЕЛЕЙ
# ============================================================
def _patterns() -> Any:
    """Хранилище списков конвейера: добавление через него сбрасывает кэш."""
    return get_pipeline().patterns


@app.get("/api/v1/lists")
def lists_index(kind: Optional[str] = None,
                _: str = Depends(require_api_key)) -> List[Dict[str, Any]]:
    return _patterns().list(kind)


@app.post("/api/v1/lists")
def lists_add(pattern: str, kind: str = "allow", note: str = "",
              api_key: str = Depends(require_admin_token)) -> Dict[str, Any]:
    try:
        row = _patterns().add(pattern, kind, note=note, created_by=api_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit.log("list_add", actor=api_key, target=pattern, detail=f"kind={kind}")
    return row


@app.delete("/api/v1/lists/{record_id}")
def lists_remove(record_id: int,
                 api_key: str = Depends(require_admin_token)) -> Dict[str, bool]:
    removed = _patterns().remove(record_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Запись не найдена")
    audit.log("list_remove", actor=api_key, target=str(record_id))
    return {"removed": removed}


# ============================================================
# КОНФИГУРАЦИЯ (секреты замаскированы)
# ============================================================
@app.get("/api/v1/config")
def config_view(_: str = Depends(require_api_key)) -> Dict[str, Any]:
    return settings.safe_dump()
