"""
Конфигурация шлюза: только переменные окружения (12-factor), секретов в коде нет.

Если ключ GigaChat не задан — сервис честно работает в эвристическом режиме и
сообщает об этом в /health и в каждом вердикте (модуль ИИ получает статус
``not_configured``, его вес перераспределяется, а не «сгорает»).

Основные переменные окружения (префикс ANTISPAM_):
    ANTISPAM_API_KEYS                ключи доступа к REST API через запятую
    ANTISPAM_ADMIN_TOKEN             токен для выпуска писем из карантина
    ANTISPAM_MTA_TOKEN               общий секрет для SMTP-фронта/милтера
    GIGACHAT_AUTH_KEY                base64-ключ Sber (Basic-токен OAuth)
    GIGACHAT_KEY_ADD/GIGACHAT_KEY_SECRET  альтернатива: пара ключа
    ANTISPAM_THRESHOLDS              JSON: {"warn":35,"hold":55,...}
    ANTISPAM_MODULE_WEIGHTS          JSON: {"heuristics":0.22,...}
"""
from __future__ import annotations

import base64
import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_prefix="antispam_",
        extra="ignore",
    )

    # ------------------------------------------------------------ приложение
    app_name: str = "AntiPhish Gateway"
    app_version: str = "2.0.0"
    debug: bool = False
    log_level: str = "INFO"
    log_json: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    workers: int = 1
    cors_origins: str = "*"

    # ------------------------------------------------------------ доступ к API
    api_keys: str = ""           # через запятую; пусто = доступ закрыт
    admin_token: str = ""        # право выпускать письма из карантина
    mta_token: str = ""          # секрет для SMTP-фронта и милтера
    rate_limit_per_ip: int = 120
    rate_limit_window: int = 60

    # ------------------------------------------------------------ лимиты
    max_email_size: int = 2_000_000
    max_text_chars: int = 60_000
    request_timeout: int = 45
    max_concurrent_scans: int = 16

    # ------------------------------------------------------------ пороги решений
    thresholds: Dict[str, int] = Field(default_factory=lambda: {
        "warn": 35, "hold": 55, "quarantine": 70, "block": 85,
    })
    grey_zone: int = 8
    module_weights: Dict[str, float] = Field(default_factory=lambda: {
        "heuristics": 0.22,
        "urls": 0.26,
        "auth": 0.22,
        "attachments": 0.12,
        "ai": 0.18,
    })

    # ------------------------------------------------------------ GigaChat
    gigachat_auth_key: str = ""
    gigachat_key_add: str = ""
    gigachat_key_secret: str = ""
    gigachat_scope: str = "GIGACHAT_API_PERS"
    gigachat_model: str = "GigaChat-2-Max"
    gigachat_oauth_url: str = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
    gigachat_api_url: str = "https://api.giga.chat/v1/chat/completions"
    gigachat_timeout: int = 20
    gigachat_retries: int = 2
    gigachat_retry_backoff: float = 0.8
    gigachat_max_tokens: int = 700
    gigachat_temperature: float = 0.05
    gigachat_ssl_verify: bool = True
    gigachat_ca_bundle: str = ""
    gigachat_cache_ttl: int = 900
    gigachat_cache_size: int = 512
    gigachat_max_chars: int = 12_000
    ai_enabled: bool = True
    # Когда ИИ вообще нужен: ниже порога быстрых модулей квота не расходуется
    ai_min_quick_score: int = 15

    # ------------------------------------------------------------ URL / RDAP / DNS
    rdap_enabled: bool = True
    rdap_base_url: str = "https://rdap.org/domain"
    rdap_timeout: int = 4
    rdap_cache_ttl: int = 86_400
    dns_check_enabled: bool = True
    follow_redirects: bool = True
    redirect_timeout: int = 5
    max_urls_per_email: int = 12
    domain_age_suspicious_days: int = 30
    domain_age_young_days: int = 180

    # ------------------------------------------------------------ вход почты
    # watch  — разбор каталога-спула (письма кладёт getmail/fetchmail);
    # smtp   — встроенный приёмный SMTP-сервер (отвечает 550 на отвергаемые);
    # disabled — только REST API.
    mta_mode: str = "watch"
    mta_spool_dir: str = str(BASE_DIR / "data" / "spool")
    mta_processed_dir: str = str(BASE_DIR / "data" / "processed")
    mta_quarantine_dir: str = str(BASE_DIR / "data" / "quarantine-eml")
    mta_poll_seconds: int = 5
    mta_smtp_host: str = "0.0.0.0"
    mta_smtp_port: int = 2525
    mta_max_message_mb: int = 25

    # ------------------------------------------------------------ хранилище
    db_path: str = str(BASE_DIR / "data" / "gateway.db")
    allowlist_path: str = str(BASE_DIR / "data" / "allowlist.json")
    quarantine_dir: str = str(BASE_DIR / "data" / "quarantine")
    quarantine_max_items: int = 5000
    quarantine_ttl_days: int = 30
    quarantine_retention_days: int = 30
    audit_log_path: str = str(BASE_DIR / "data" / "audit" / "decisions.jsonl")
    audit_flush_interval: float = 2.0
    audit_batch_size: int = 200
    audit_queue_size: int = 20_000

    # ------------------------------------------------------------ валидация
    @field_validator("thresholds", "module_weights", mode="before")
    @classmethod
    def _parse_json_env(cls, value):
        """Словарь можно задать одной переменной окружения в JSON."""
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Ожидается JSON-объект, получено: {value!r}") from exc
        return value

    @field_validator("cors_origins")
    @classmethod
    def _validate_cors(cls, value: str) -> str:
        return (value or "").strip() or "*"

    @field_validator("log_level")
    @classmethod
    def _upper_level(cls, value: str) -> str:
        return (value or "INFO").upper()

    @field_validator("mta_mode")
    @classmethod
    def _validate_mode(cls, value: str) -> str:
        mode = (value or "watch").lower()
        if mode not in {"watch", "smtp", "disabled"}:
            raise ValueError("ANTISPAM_MTA_MODE должен быть watch | smtp | disabled")
        return mode

    # ------------------------------------------------------------ производные
    @property
    def key_list(self) -> List[str]:
        return [k.strip() for k in self.api_keys.split(",") if k.strip()]

    @property
    def cors_origin_list(self) -> List[str]:
        if self.cors_origins.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def auth_header_value(self) -> str:
        """Basic-токен OAuth: готовый base64 либо сборка из key_add:key_secret."""
        if self.gigachat_auth_key:
            return self.gigachat_auth_key
        if self.gigachat_key_add and self.gigachat_key_secret:
            raw = f"{self.gigachat_key_add}:{self.gigachat_key_secret}"
            return base64.b64encode(raw.encode()).decode()
        return ""

    @property
    def ai_configured(self) -> bool:
        return bool(self.ai_enabled and self.auth_header_value)

    @property
    def ssl_verify(self) -> bool | str:
        """verify=False не используется никогда; при необходимости — свой CA."""
        if self.gigachat_ca_bundle:
            return self.gigachat_ca_bundle
        return self.gigachat_ssl_verify

    @property
    def weights_total(self) -> float:
        return sum(self.module_weights.values()) or 1.0

    @property
    def data_dirs(self) -> List[Path]:
        return [
            Path(self.db_path).parent,
            Path(self.quarantine_dir),
            Path(self.allowlist_path).parent,
            Path(self.audit_log_path).parent,
            Path(self.mta_spool_dir),
            Path(self.mta_processed_dir),
            Path(self.mta_quarantine_dir),
        ]

    def ensure_dirs(self) -> None:
        for path in self.data_dirs:
            path.mkdir(parents=True, exist_ok=True)

    def safe_dump(self) -> Dict[str, object]:
        """Снимок настроек для /api/v1/config: секреты замаскированы."""
        data = dict(self.model_dump())
        for key in list(data):
            if any(s in key for s in ("key", "secret", "token")):
                data[key] = "***" if data[key] else ""
        return data


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
