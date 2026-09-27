"""
Проверка ключей доступа.

Ключи не хранятся в открытом виде: в базе и в журнале остаётся только отпечаток
(SHA-256), сравнение incoming-ключа выполняется через hmac.compare_digest, чтобы
не светить длину/содержимое через время ответа.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import List, Optional, Sequence, Union

KeysLike = Union[str, Sequence[str]]


def _as_list(keys: KeysLike) -> List[str]:
    if isinstance(keys, str):
        return [k.strip() for k in keys.split(",") if k.strip()]
    return [str(k).strip() for k in keys if str(k).strip()]


def hash_key(value: str) -> str:
    """Полный хеш ключа — им можно сравнивать в БД."""
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def fingerprint(value: str) -> str:
    """Короткий отпечаток для журналов (8 символов, не позволяет восстановить ключ)."""
    return hash_key(value)[:8] if value else ""


def check_api_key(provided: Optional[str], keys: KeysLike) -> bool:
    """Constant-time сравнение с любым из разрешённых ключей."""
    allowed = _as_list(keys)
    if not provided or not allowed:
        return False
    candidate = provided.strip()
    matched = False
    for key in allowed:
        # сравниваем хеши: одинаковая стоимость на любой длине ключа
        if hmac.compare_digest(hash_key(candidate), hash_key(key)):
            matched = True
    return matched


def check_admin_token(provided: Optional[str], admin_token: str) -> bool:
    if not admin_token:
        return False
    return hmac.compare_digest(hash_key(provided or ""), hash_key(admin_token))


def mask_secret(value: str, keep: int = 4) -> str:
    """Маска для журнала/UI: первые keep символов и длина (тело секрета не раскрывается)."""
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "…" + str(len(value))
