"""
Белые/чёрные списки отправителей поверх SQLite.

Записи живут в таблице list_entries (см. storage.db), наружу отдаётся dataclass
с атрибутами: движку скоринга нужны ``entry.pattern`` / ``entry.note``, а API —
обычные dict. Поддержаны три способа совпадения: точный адрес, домен (включая
поддомены) и regex вида ``re:...`` по адресу, домену или тексту письма.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.storage import db

logger = logging.getLogger("gateway.patterns")


@dataclass
class PatternEntry:
    id: int
    pattern: str
    kind: str
    entry_type: str
    note: str = ""
    created_at: str = ""
    created_by: str = ""
    expires_at: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "pattern": self.pattern, "kind": self.kind,
            "entry_type": self.entry_type, "note": self.note,
            "created_at": self.created_at, "created_by": self.created_by,
            "expires_at": self.expires_at,
        }


def _to_entry(row: Dict[str, Any]) -> PatternEntry:
    return PatternEntry(
        id=int(row.get("id") or 0),
        pattern=row.get("pattern", ""),
        kind=row.get("kind", "allow"),
        entry_type=row.get("entry_type", "domain"),
        note=row.get("note", "") or "",
        created_at=row.get("created_at", "") or "",
        created_by=row.get("created_by", "") or "",
        expires_at=row.get("expires_at"),
    )


class PatternStore:
    """Тонкая обёртка над list_entries: совпадения, regex-правила, срок действия."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        # аргументы пути принимаются для совместимости со старым вызовом —
        # источником истины является БД из конфигурации
        self._cache: Dict[str, List[Dict[str, Any]]] = {}

    # ---------------------------------------------------------------- CRUD
    def add(self, pattern: str, kind: str = "allow", note: str = "",
            created_by: str = "", *, expires_in_days: Optional[int] = None) -> Dict[str, Any]:
        row = db.list_add(pattern, kind, note=note, created_by=created_by,
                          expires_in_days=expires_in_days)
        self._cache.clear()
        return row

    def add_domain(self, domain: str, kind: str = "allow", note: str = "",
                   created_by: str = "") -> Dict[str, Any]:
        return self.add(domain, kind, note, created_by)

    def add_regex(self, regex: str, kind: str = "deny", note: str = "",
                  created_by: str = "") -> Dict[str, Any]:
        return self.add(f"re:{regex}", kind, note, created_by)

    def remove(self, record_id: int) -> bool:
        removed = db.list_remove(int(record_id))
        self._cache.clear()
        return removed

    def remove_pattern(self, pattern: str, kind: str = "allow") -> bool:
        wanted = (pattern or "").lower().strip().lstrip("@")
        for row in self.list(kind):
            if row["pattern"] == wanted:
                return self.remove(row["id"])
        return False

    # -------------------------------------------------------------- чтение
    def list(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        cache_key = kind or "all"
        if cache_key not in self._cache:
            self._cache[cache_key] = db.list_all(kind)
        return self._cache[cache_key]

    def entries(self, kind: Optional[str] = None) -> List[PatternEntry]:
        return [_to_entry(row) for row in self.list(kind)]

    def clear_cache(self) -> None:
        self._cache.clear()

    # ------------------------------------------------------------ совпадение
    @staticmethod
    def _matches(row: Dict[str, Any], address: str, domain: str) -> bool:
        pattern = row["pattern"]
        if row.get("entry_type") == "regex" or pattern.startswith("re:"):
            regex = pattern[3:] if pattern.startswith("re:") else pattern
            try:
                return bool(re.search(regex, address) or re.search(regex, domain))
            except re.error:
                logger.warning("Некорректный regex в списке: %s", pattern)
                return False
        if pattern == address or pattern == domain:
            return True
        return domain.endswith("." + pattern)

    def match(self, value: str, kind: str = "allow") -> Optional[PatternEntry]:
        """Подходит ли адрес или домен под запись списка."""
        address = (value or "").lower().strip()
        if not address:
            return None
        domain = address.rsplit("@", 1)[-1] if "@" in address else address
        for row in self.list(kind):
            if self._matches(row, address, domain):
                return _to_entry(row)
        return None

    def regex_match(self, text: str, kind: str = "deny") -> Optional[PatternEntry]:
        """Regex-правило по произвольному тексту (тема + имя + фрагмент тела)."""
        if not text:
            return None
        lowered = text.lower()
        for row in self.list(kind):
            pattern = row["pattern"]
            if not (row.get("entry_type") == "regex" or pattern.startswith("re:")):
                continue
            try:
                if re.search(pattern[3:], lowered):
                    return _to_entry(row)
            except re.error:
                logger.warning("Некорректный regex в списке: %s", pattern)
        return None

    def expiring(self, days: int = 3) -> List[Dict[str, Any]]:
        """Записи со скорым окончанием срока — чтобы админ не потерял партнёра."""
        horizon = datetime.now(timezone.utc) + timedelta(days=days)
        result = []
        for row in db.list_all(include_expired=False):
            raw = row.get("expires_at")
            if not raw:
                continue
            try:
                moment = datetime.fromisoformat(raw)
            except (TypeError, ValueError):
                continue
            if moment < horizon:
                result.append(row)
        return result
