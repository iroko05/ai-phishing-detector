"""
SQLite-хранилище шлюза: журнал разборов, карантин, списки и журналы действий.

Выбор SQLite а не Postgres/JSON-файлов: шлюз живёт в одном контейнере с
docker-volume, данные нужны сразу (статистика, объяснение решения, история
отправителя), а конкурентная запись одна — WAL-режим её держит.

Схема:
    analyses         — вердикты по письмам (payload_json = полный разбор)
    quarantine       — спорные/отклонённые письма с исходным RFC822
    list_entries     — белые и чёрные списки (домен/адрес/regex)
    feedback         — разметка оператора (phishing/legitimate)
    audit_log        — действия людей и ключей
    mta_health       — последний heartbeat SMTP-фронта
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from app.config import get_settings

logger = logging.getLogger("gateway.storage")

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'api',
    api_key_hash TEXT NOT NULL DEFAULT '',
    message_id TEXT NOT NULL DEFAULT '',
    sender TEXT NOT NULL DEFAULT '',
    sender_domain TEXT NOT NULL DEFAULT '',
    recipient TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    score INTEGER NOT NULL DEFAULT 0,
    level TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    phishing_type TEXT NOT NULL DEFAULT '',
    ai_status TEXT NOT NULL DEFAULT '',
    latency_ms INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_sender ON analyses(sender_domain);
CREATE INDEX IF NOT EXISTS idx_analyses_action ON analyses(action);

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    analysis_id INTEGER,
    sender TEXT NOT NULL DEFAULT '',
    recipient TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    score INTEGER NOT NULL DEFAULT 0,
    action TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    phishing_type TEXT NOT NULL DEFAULT '',
    raw_source TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    handled_at TEXT,
    handled_by TEXT,
    release_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status, created_at DESC);

CREATE TABLE IF NOT EXISTS list_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'allow',
    entry_type TEXT NOT NULL DEFAULT 'domain',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    expires_at TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE (pattern, kind)
);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    analysis_id INTEGER NOT NULL,
    label TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    marked_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_feedback_analysis ON feedback(analysis_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    ok INTEGER NOT NULL DEFAULT 1,
    ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

CREATE TABLE IF NOT EXISTS mta_health (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_seen TEXT,
    mode TEXT NOT NULL DEFAULT '',
    queue_size INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT ''
);
"""

_local = threading.local()
_init_lock = threading.Lock()
_initialized_paths: set[str] = set()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def db_path() -> Path:
    return Path(get_settings().db_path)


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=15, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def get_db() -> sqlite3.Connection:
    """Одно соединение на поток: SQLite нельзя передавать между потоками."""
    path = db_path()
    cached = getattr(_local, "connection", None)
    if cached is not None and getattr(_local, "path", None) == str(path):
        return cached
    connection = _connect(path)
    _local.connection = connection
    _local.path = str(path)
    if str(path) not in _initialized_paths:
        with _init_lock:
            if str(path) not in _initialized_paths:
                connection.executescript(SCHEMA)
                connection.commit()
                _initialized_paths.add(str(path))
    return connection


@contextmanager
def session() -> Iterator[sqlite3.Connection]:
    """Транзакционный контекст: commit при успехе, rollback при исключении."""
    connection = get_db()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def init_db(path: Optional[Path] = None) -> None:
    """Явная инициализация (вызывается на старте приложения и в тестах)."""
    if path is not None:
        settings = get_settings()
        settings.db_path = str(path)
        _initialized_paths.discard(str(path))
    connection = get_db()
    connection.executescript(SCHEMA)
    connection.commit()


def reset_state() -> None:
    """Для тестов: сбрасываем кэш соединений и флаг инициализации."""
    connection = getattr(_local, "connection", None)
    if connection is not None:
        try:
            connection.close()
        except sqlite3.Error:
            pass
    _local.connection = None
    _local.path = None
    _initialized_paths.clear()


# ============================================================ разборы
def log_analysis(result: Any, *, source: str = "api", api_key: str = "") -> int:
    """Сохраняет вердикт и возвращает id записи."""
    from app.security.keys import hash_key

    payload = {
        "summary": getattr(result, "summary", ""),
        "decision_reason": result.decision_reason,
        "confidence": result.confidence,
        "weights": result.weights,
        "modules_status": result.modules_status,
        "signals": [s.model_dump() for s in result.signals],
        "evidence": [e.model_dump() for e in result.evidence],
        "links": [link.model_dump() for link in result.links],
        "domains": [domain.model_dump() for domain in result.domains],
        "url_details": [v.model_dump() for v in result.url_details],
        "attachments": [a.model_dump() for a in result.attachments],
        "auth": result.auth.model_dump(),
        "auth_report": result.auth_report.model_dump(),
        "ai_report": result.ai_report.model_dump(),
        "url_analysis": result.url_analysis.model_dump(),
        "heuristics_report": result.heuristics_report.model_dump(),
        "attachment_report": result.attachment_report.model_dump(),
        "suggested_actions": result.suggested_actions,
        "aggregation": getattr(result, "aggregation", {}) or {},
        "hard_rules": getattr(result, "hard_rules", []) or [],
        "direction": result.direction,
        "targeted": result.targeted,
        "allowlisted": result.allowlisted,
        "engine_version": result.engine_version,
    }
    with session() as connection:
        cursor = connection.execute(
            """
            INSERT INTO analyses (created_at, source, api_key_hash, message_id, sender,
                                  sender_domain, recipient, subject, score, level, action,
                                  reason, phishing_type, ai_status, latency_ms, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _iso(utcnow()), source, hash_key(api_key)[:32],
                getattr(result, "message_id", "") or "",
                getattr(result, "sender", "") or payload.get("sender", ""),
                _domain_of(getattr(result, "sender", "") or ""),
                getattr(result, "recipient", "") or "",
                getattr(result, "subject", "") or "",
                result.risk_score, result.risk_level, result.action,
                result.decision_reason[:500], result.phishing_type,
                result.modules_status.get("ai", "unknown"), result.latency_ms,
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        return int(cursor.lastrowid)


def _domain_of(address: str) -> str:
    address = (address or "").strip().lower()
    return address.rsplit("@", 1)[-1] if "@" in address else address


def get_analysis(analysis_id: int) -> Optional[Dict[str, Any]]:
    with session() as connection:
        row = connection.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
    return _analysis_dict(row) if row else None


def _analysis_dict(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    try:
        item["payload"] = json.loads(item.pop("payload_json") or "{}")
    except json.JSONDecodeError:
        item["payload"] = {}
    return item


def recent_analyses(limit: int = 50, *, action: Optional[str] = None,
                    min_score: int = 0, sender_domain: Optional[str] = None,
                    since: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Список разборов для таблицы на дашборде (без тяжёлого payload)."""
    query = ("SELECT id, created_at, source, message_id, sender, sender_domain, subject,"
             " score, level, action, reason, phishing_type, ai_status, latency_ms,"
             " payload_json FROM analyses")
    where: List[str] = []
    params: List[Any] = []
    if action:
        where.append("action = ?")
        params.append(action)
    if min_score:
        where.append("score >= ?")
        params.append(min_score)
    if sender_domain:
        where.append("sender_domain = ?")
        params.append(sender_domain.lower())
    if since:
        where.append("created_at >= ?")
        params.append(_iso(since))
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    with session() as connection:
        rows = connection.execute(query, params).fetchall()
    out: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["summary"] = json.loads(item.pop("payload_json") or "{}").get("summary", "")
        except json.JSONDecodeError:
            item["summary"] = ""
        out.append(item)
    return out


# ============================================================ карантин
def quarantine_add(result: Any, *, raw_source: str, recipient: str = "",
                   source: str = "api") -> int:
    with session() as connection:
        cursor = connection.execute(
            """
            INSERT INTO quarantine (created_at, analysis_id, sender, recipient, subject,
                                    score, action, reason, phishing_type, raw_source, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                _iso(utcnow()), getattr(result, "id", None),
                getattr(result, "sender", "") or "", recipient,
                getattr(result, "subject", "") or "",
                result.risk_score, result.action,
                result.decision_reason[:500], result.phishing_type,
                (raw_source or "")[:200_000],
            ),
        )
        return int(cursor.lastrowid)


def quarantine_list(status: Optional[str] = "pending", limit: int = 50,
                    offset: int = 0) -> List[Dict[str, Any]]:
    query = ("SELECT id, created_at, analysis_id, sender, recipient, subject, score,"
             " action, reason, phishing_type, status, handled_at, handled_by, release_note,"
             " length(raw_source) AS raw_size FROM quarantine")
    params: List[Any] = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
    with session() as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]


def quarantine_get(record_id: int, *, with_source: bool = True) -> Optional[Dict[str, Any]]:
    columns = "*" if with_source else ("id, created_at, analysis_id, sender, recipient,"
                                       " subject, score, action, reason, phishing_type,"
                                       " status, handled_at, handled_by, release_note")
    with session() as connection:
        row = connection.execute(
            f"SELECT {columns} FROM quarantine WHERE id = ?", (record_id,)
        ).fetchone()
    return dict(row) if row else None


def quarantine_handle(record_id: int, status: str, *, operator: str = "",
                      note: str = "") -> bool:
    if status not in {"released", "rejected", "deleted"}:
        raise ValueError(f"Недопустимый статус карантина: {status}")
    with session() as connection:
        cursor = connection.execute(
            """
            UPDATE quarantine SET status = ?, handled_at = ?, handled_by = ?, release_note = ?
            WHERE id = ? AND status = 'pending'
            """,
            (status, _iso(utcnow()), operator[:64], note[:500], record_id),
        )
        return cursor.rowcount > 0


def quarantine_stats() -> Dict[str, Any]:
    with session() as connection:
        rows = connection.execute(
            "SELECT status, COUNT(*) AS n FROM quarantine GROUP BY status"
        ).fetchall()
    counts = {row["status"]: row["n"] for row in rows}
    return {"pending": counts.get("pending", 0),
            "released": counts.get("released", 0),
            "rejected": counts.get("rejected", 0),
            "total": sum(counts.values())}


def quarantine_prune(days: int) -> int:
    """Удаляет просроченные записи — их не держим вечно (GDPR/диск)."""
    cutoff = _iso(utcnow() - timedelta(days=max(1, days)))
    with session() as connection:
        cursor = connection.execute(
            "DELETE FROM quarantine WHERE created_at < ? AND status <> 'pending'",
            (cutoff,),
        )
        return cursor.rowcount


# ============================================================ списки
def list_add(pattern: str, kind: str = "allow", *, note: str = "",
             entry_type: str = "auto", created_by: str = "",
             expires_in_days: Optional[int] = None) -> Dict[str, Any]:
    from app.security.keys import fingerprint

    pattern = (pattern or "").lower().strip().lstrip("@")
    if not pattern:
        raise ValueError("Пустой шаблон")
    if kind not in {"allow", "deny"}:
        raise ValueError("kind должен быть allow или deny")
    if entry_type == "auto":
        entry_type = "regex" if pattern.startswith("re:") else (
            "address" if "@" in pattern else "domain")
    expires_at = (_iso(utcnow() + timedelta(days=expires_in_days))
                  if expires_in_days else None)
    with session() as connection:
        connection.execute(
            """
            INSERT INTO list_entries (pattern, kind, entry_type, note, created_at,
                                      created_by, expires_at, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(pattern, kind) DO UPDATE SET
                note = excluded.note,
                entry_type = excluded.entry_type,
                expires_at = excluded.expires_at,
                enabled = 1
            """,
            (pattern, kind, entry_type, note[:280], _iso(utcnow()),
             fingerprint(created_by) or "system", expires_at),
        )
        row = connection.execute(
            "SELECT * FROM list_entries WHERE pattern = ? AND kind = ?",
            (pattern, kind),
        ).fetchone()
    return dict(row)


def list_remove(record_id: int) -> bool:
    with session() as connection:
        cursor = connection.execute("DELETE FROM list_entries WHERE id = ?", (record_id,))
        return cursor.rowcount > 0


def list_all(kind: Optional[str] = None, *, include_expired: bool = False) -> List[Dict[str, Any]]:
    query = "SELECT * FROM list_entries WHERE enabled = 1"
    params: List[Any] = []
    if kind:
        query += " AND kind = ?"
        params.append(kind)
    query += " ORDER BY pattern"
    with session() as connection:
        rows = [dict(row) for row in connection.execute(query, params).fetchall()]
    now = utcnow()
    result = []
    for row in rows:
        expires = row.get("expires_at")
        row["expired"] = bool(expires and datetime.fromisoformat(expires) < now)
        if include_expired or not row["expired"]:
            result.append(row)
    return result


def list_matches(kind: str, sender: str) -> Optional[Dict[str, Any]]:
    """Ищем совпадение: точный адрес, домен/поддомен или regex по адресу."""
    import re

    sender = (sender or "").lower().strip()
    domain = _domain_of(sender)
    for entry in list_all(kind):
        pattern = entry["pattern"]
        if entry["entry_type"] == "regex":
            try:
                if re.search(pattern[3:], sender) or re.search(pattern[3:], domain):
                    return entry
            except re.error:
                logger.warning("Некорректный regex в списке: %s", pattern)
                continue
        if pattern == sender or pattern == domain:
            return entry
        if domain.endswith("." + pattern):
            return entry
    return None


# ============================================================ обратная связь
def feedback_add(analysis_id: int, label: str, *, note: str = "",
                 marked_by: str = "") -> Dict[str, Any]:
    from app.security.keys import fingerprint

    if label not in {"phishing", "legitimate", "spam", "benign"}:
        raise ValueError("label: phishing|legitimate|spam|benign")
    if get_analysis(analysis_id) is None:
        raise KeyError(f"Разбор {analysis_id} не найден")
    with session() as connection:
        cursor = connection.execute(
            "INSERT INTO feedback (created_at, analysis_id, label, note, marked_by)"
            " VALUES (?, ?, ?, ?, ?)",
            (_iso(utcnow()), analysis_id, label, note[:500],
             fingerprint(marked_by) or "operator"),
        )
        row = connection.execute(
            "SELECT * FROM feedback WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
    return dict(row)


def feedback_recent(limit: int = 50) -> List[Dict[str, Any]]:
    with session() as connection:
        rows = connection.execute(
            """
            SELECT f.*, a.sender, a.subject, a.score, a.action
            FROM feedback f LEFT JOIN analyses a ON a.id = f.analysis_id
            ORDER BY f.id DESC LIMIT ?
            """,
            (max(1, min(int(limit), 500)),),
        ).fetchall()
    return [dict(row) for row in rows]


def feedback_stats() -> Dict[str, Any]:
    with session() as connection:
        rows = connection.execute(
            "SELECT label, COUNT(*) AS n FROM feedback GROUP BY label"
        ).fetchall()
    return {row["label"]: row["n"] for row in rows}


# ============================================================ журнал действий
def audit_write(action: str, *, actor: str = "", target: str = "", detail: str = "",
                ok: bool = True, ip: str = "") -> None:
    with session() as connection:
        connection.execute(
            "INSERT INTO audit_log (created_at, action, actor, target, detail, ok, ip)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_iso(utcnow()), action, actor[:64], target[:200], detail[:500],
             1 if ok else 0, ip[:64]),
        )


def audit_recent(limit: int = 100, action: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM audit_log"
    params: List[Any] = []
    if action:
        query += " WHERE action = ?"
        params.append(action)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    with session() as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]


def audit_stats(days: int = 7) -> Dict[str, Any]:
    since = _iso(utcnow() - timedelta(days=days))
    with session() as connection:
        rows = connection.execute(
            "SELECT action, COUNT(*) AS n, SUM(1 - ok) AS failures FROM audit_log"
            " WHERE created_at >= ? GROUP BY action ORDER BY n DESC",
            (since,),
        ).fetchall()
    return {"by_action": {row["action"]: {"count": row["n"],
                                          "failures": row["failures"] or 0}
                          for row in rows},
            "window_days": days}


# ============================================================ MTA heartbeat
def mta_heartbeat(*, mode: str, queue_size: int = 0, detail: str = "") -> None:
    with session() as connection:
        connection.execute(
            """
            INSERT INTO mta_health (id, last_seen, mode, queue_size, detail)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen,
                                           mode = excluded.mode,
                                           queue_size = excluded.queue_size,
                                           detail = excluded.detail
            """,
            (_iso(utcnow()), mode, queue_size, detail[:200]),
        )


def mta_last_seen() -> Optional[str]:
    with session() as connection:
        row = connection.execute("SELECT last_seen FROM mta_health WHERE id = 1").fetchone()
    return row["last_seen"] if row else None


# ============================================================ статистика
def since_iso(days: int) -> str:
    """Граница периода в том же ISO-формате, что и созданные записи."""
    return _since(days)


def _since(days: int) -> str:
    return _iso(utcnow() - timedelta(days=days))


def stats_overall() -> Dict[str, Any]:
    with session() as connection:
        totals = connection.execute(
            """
            SELECT COUNT(*) AS total, AVG(score) AS avg_score,
                   SUM(CASE WHEN action IN ('quarantine','block') THEN 1 ELSE 0 END) AS blocked,
                   SUM(CASE WHEN action = 'hold' THEN 1 ELSE 0 END) AS held,
                   SUM(CASE WHEN action = 'warn' THEN 1 ELSE 0 END) AS warned,
                   SUM(CASE WHEN action = 'allow' THEN 1 ELSE 0 END) AS delivered,
                   SUM(CASE WHEN ai_status = 'ok' THEN 1 ELSE 0 END) AS ai_ok
            FROM analyses
            """
        ).fetchone()
        quarantine = quarantine_stats()
    total = int(totals["total"] or 0)
    return {
        "total": total,
        "avg_score": round(float(totals["avg_score"] or 0.0), 1),
        "blocked": int(totals["blocked"] or 0),
        "held": int(totals["held"] or 0),
        "warned": int(totals["warned"] or 0),
        "delivered": int(totals["delivered"] or 0),
        "ai_share": round((int(totals["ai_ok"] or 0) / total), 3) if total else 0.0,
        "quarantine_pending": quarantine["pending"],
        "quarantine_released": quarantine["released"],
    }


def stats_period(since: str) -> Dict[str, Any]:
    with session() as connection:
        rows = connection.execute(
            "SELECT action, level, COUNT(*) AS n FROM analyses WHERE created_at >= ?"
            " GROUP BY action, level",
            (since,),
        ).fetchall()
    by_action: Dict[str, int] = {}
    by_level: Dict[str, int] = {}
    for row in rows:
        by_action[row["action"]] = by_action.get(row["action"], 0) + row["n"]
        by_level[row["level"]] = by_level.get(row["level"], 0) + row["n"]
    return {"by_action": by_action, "by_level": by_level}


def stats_daily(days: int = 7) -> List[Dict[str, Any]]:
    since = _since(days)
    with session() as connection:
        rows = connection.execute(
            """
            SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total,
                   SUM(CASE WHEN action IN ('quarantine','block') THEN 1 ELSE 0 END) AS blocked,
                   MAX(score) AS max_score, AVG(score) AS avg_score
            FROM analyses WHERE created_at >= ? GROUP BY day ORDER BY day
            """,
            (since,),
        ).fetchall()
    return [{"day": row["day"], "total": row["total"], "blocked": row["blocked"],
             "max_score": row["max_score"],
             "avg_score": round(float(row["avg_score"] or 0), 1)} for row in rows]


def stats_hourly(hours: int = 24) -> List[Dict[str, Any]]:
    since = _iso(utcnow() - timedelta(hours=hours))
    with session() as connection:
        rows = connection.execute(
            "SELECT substr(created_at, 1, 13) AS hour, COUNT(*) AS total,"
            " SUM(CASE WHEN action IN ('quarantine','block') THEN 1 ELSE 0 END) AS blocked"
            " FROM analyses WHERE created_at >= ? GROUP BY hour ORDER BY hour",
            (since,),
        ).fetchall()
    return [dict(row) for row in rows]


def stats_by_type(since: str) -> List[Dict[str, Any]]:
    with session() as connection:
        rows = connection.execute(
            "SELECT phishing_type, COUNT(*) AS n FROM analyses WHERE created_at >= ?"
            " AND phishing_type <> '' GROUP BY phishing_type ORDER BY n DESC",
            (since,),
        ).fetchall()
    return [dict(row) for row in rows]


def stats_by_action(since: str) -> List[Dict[str, Any]]:
    with session() as connection:
        rows = connection.execute(
            "SELECT action, COUNT(*) AS n, AVG(score) AS avg_score FROM analyses"
            " WHERE created_at >= ? GROUP BY action ORDER BY n DESC",
            (since,),
        ).fetchall()
    return [{"action": row["action"], "n": row["n"],
             "avg_score": round(float(row["avg_score"] or 0), 1)} for row in rows]


def top_senders(since: str, limit: int = 10) -> List[Dict[str, Any]]:
    with session() as connection:
        rows = connection.execute(
            "SELECT sender_domain, COUNT(*) AS n,"
            " SUM(CASE WHEN action IN ('quarantine','block') THEN 1 ELSE 0 END) AS positives,"
            " MAX(score) AS max_score FROM analyses WHERE created_at >= ?"
            " AND sender_domain <> '' GROUP BY sender_domain"
            " ORDER BY positives DESC, n DESC LIMIT ?",
            (since, max(1, min(int(limit), 100))),
        ).fetchall()
    return [dict(row) for row in rows]


def top_rules(days: int = 7, limit: int = 10) -> List[Dict[str, Any]]:
    """Самые частые сработавшие правила — по payload разборов."""
    since = _since(days)
    counter: Dict[str, int] = {}
    with session() as connection:
        rows = connection.execute(
            "SELECT payload_json FROM analyses WHERE created_at >= ?"
            " ORDER BY id DESC LIMIT 2000",
            (since,),
        ).fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except json.JSONDecodeError:
            continue
        for signal in payload.get("signals") or []:
            if int(signal.get("points") or 0) > 0:
                rule = signal.get("rule_id") or signal.get("title") or "?"
                counter[rule] = counter.get(rule, 0) + 1
    ordered = sorted(counter.items(), key=lambda item: item[1], reverse=True)
    return [{"rule_id": rule, "hits": hits} for rule, hits in ordered[:limit]]


def top_urls(days: int = 7, limit: int = 10) -> List[Dict[str, Any]]:
    since = _since(days)
    counter: Dict[str, Dict[str, Any]] = {}
    with session() as connection:
        rows = connection.execute(
            "SELECT payload_json FROM analyses WHERE created_at >= ?"
            " ORDER BY id DESC LIMIT 2000",
            (since,),
        ).fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except json.JSONDecodeError:
            continue
        for link in payload.get("links") or []:
            domain = link.get("registrar_domain") or link.get("domain") or "?"
            entry = counter.setdefault(domain, {"domain": domain, "hits": 0,
                                                "suspicious": 0, "max_score": 0})
            entry["hits"] += 1
            entry["suspicious"] += 1 if link.get("suspicious") else 0
            entry["max_score"] = max(entry["max_score"], int(link.get("score") or 0))
    ordered = sorted(counter.values(),
                     key=lambda item: (item["suspicious"], item["hits"]), reverse=True)
    return ordered[:limit]


def sender_history(domain: str, *, days: int = 30, limit: int = 50) -> Dict[str, Any]:
    """История отправителя — нужен ли был ИИ, что решали, есть ли повторные атаки."""
    domain = _domain_of(domain)
    since = _since(days)
    with session() as connection:
        rows = connection.execute(
            "SELECT id, created_at, subject, score, action, phishing_type, ai_status"
            " FROM analyses WHERE sender_domain = ? AND created_at >= ?"
            " ORDER BY id DESC LIMIT ?",
            (domain, since, max(1, min(int(limit), 200))),
        ).fetchall()
        aggregates = connection.execute(
            "SELECT COUNT(*) AS n,"
            " SUM(CASE WHEN action IN ('quarantine','block') THEN 1 ELSE 0 END) AS positives"
            " FROM analyses WHERE sender_domain = ? AND created_at >= ?",
            (domain, since),
        ).fetchone()
    total = int(aggregates["n"] or 0)
    positives = int(aggregates["positives"] or 0)
    return {
        "domain": domain,
        "window_days": days,
        "total": total,
        "positives": positives,
        "positive_rate": round(positives / total, 3) if total else 0.0,
        "items": [dict(row) for row in rows],
    }


# ============================================================ имена для API-слоя
# main.py работает с «глаголами» бизнес-уровня; ниже — мосты к функциям выше,
# чтобы имена в REST-слое оставались читаемыми и стабильными.

def recent_logs(limit: int = 50, action: Optional[str] = None,
                min_score: int = 0) -> List[Dict[str, Any]]:
    """Журнал разборов с полным payload — нужен для /explain и /letter."""
    query = "SELECT * FROM analyses"
    conditions: List[str] = []
    params: List[Any] = []
    if action:
        conditions.append("action = ?")
        params.append(action)
    if min_score:
        conditions.append("score >= ?")
        params.append(min_score)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    with session() as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]


def log_feedback(analysis_id: int, label: str, note: str = "",
                 marked_by: str = "") -> bool:
    """Разметка оператора; False — если разбора нет (API отдаст 404)."""
    try:
        feedback_add(analysis_id, label, note=note, marked_by=marked_by)
    except (KeyError, ValueError):
        return False
    return True


def quarantine_save(*, analysis_id: Optional[int], score: int, action: str,
                    sender: str, subject: str, reason: str, raw_source: str,
                    phishing_type: str = "", recipient: str = "") -> int:
    """Постановка письма в карантин из REST-слоя (именованными аргументами)."""
    with session() as connection:
        cursor = connection.execute(
            """
            INSERT INTO quarantine (created_at, analysis_id, sender, recipient, subject,
                                    score, action, reason, phishing_type, raw_source, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            """,
            (_iso(utcnow()), analysis_id, sender, recipient, subject, score, action,
             reason[:500], phishing_type, (raw_source or "")[:200_000]),
        )
        return int(cursor.lastrowid)


def quarantine_update(record_id: int, action: str, operator: str = "",
                      note: str = "") -> bool:
    """release → released, reject → rejected; False, если запись уже обработана."""
    status = {"release": "released", "reject": "rejected",
              "released": "released", "rejected": "rejected"}.get(action)
    if not status:
        return False
    return quarantine_handle(record_id, status, operator=operator, note=note)
