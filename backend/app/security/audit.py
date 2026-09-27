"""
Журнал административных действий (кто, чем, когда).

Пишется в ту же SQLite, что и разборы, — так «что произошло в системе» остаётся
одним связным набором данных: выпуск из карантина, правка списков, отказы в
доступе. Актор фиксируется отпечатком ключа, а не самим ключом.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.security.keys import fingerprint
from app.storage import db

logger = logging.getLogger("gateway.audit")


class AuditTrail:
    """Тонкая обёртка над таблицей audit_log: не бросает исключений наружу."""

    def log(self, action: str, *, actor: str = "", target: str = "",
            detail: str = "", ok: bool = True, ip: str = "") -> None:
        try:
            db.audit_write(
                action,
                actor=fingerprint(actor) if actor else (actor or "system"),
                target=target, detail=detail, ok=ok, ip=ip,
            )
        except Exception:  # noqa: BLE001 — журнал не должен ронять запрос
            logger.exception("не удалось записать в журнал действий: %s", action)

    # совместимость со старым вызовом audit.event(...)
    def event(self, action: str, **kwargs: Any) -> None:
        self.log(action, **kwargs)

    def recent(self, limit: int = 100, action: Optional[str] = None) -> List[Dict[str, Any]]:
        return db.audit_recent(limit=limit, action=action)

    def stats(self, days: int = 7) -> Dict[str, Any]:
        return db.audit_stats(days=days)


audit = AuditTrail()
