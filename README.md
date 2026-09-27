# AI-Phishing Gateway

Автоматизированный шлюз анализа корпоративной почты на фишинг, BEC-атаки
(Business Email Compromise) и социальную инженерию: эвристика + анализ ссылок
и заголовков + вложения + LLM-вердикт (GigaChat) → взвешенное решение с
объяснением каждого балла.

Состоит из двух сервисов:

| Сервис   | Назначение                                                        | Порт      |
|----------|-------------------------------------------------------------------|-----------|
| backend  | REST API, конвейер анализа, MTA-интеграция, SQLite-хранилище      | 8000, 2525|
| frontend | SOC-дашборд на Next.js (API-прокси, без CORS и ключей в браузере) | 3000      |

## Архитектура

```
                        ┌────────────────────────────────────────────────┐
 Почтовый поток          │                backend (FastAPI)               │
                        │                                                │
 MTA (Postfix/Exim) ────► SMTP-фронт :2525 ──┐                           │
 getmail/fetchmail ────► спул data/spool ────┤   app.mta.watcher         │
 REST-клиенты ─────────► /api/v1/gateway/… ──┤        │                  │
 .eml с дашборда ──────► /api/v1/gateway/… ──┘        ▼                  │
                        │                     app.engine.pipeline        │
                        │                     ┌──► heuristics  (правила) │
                        │                     ├──► email_auth  (SPF/     │
                        │                     │        DKIM/DMARC)       │
                        │                     ├──► url_intel   (структура│
                        │                     │        доменов, бренды,  │
                        │                     │        RDAP/DNS/редирект)│
                        │                     ├──► attachments (маски-   │
                        │                     │        ровка, архивы)    │
                        │                     └──► gigachat    (LLM,     │
                        │                          выборочно, с кэшем)   │
                        │                                ▼                │
                        │                     app.engine.scoring         │
                        │                     (взвешенная агрегация +    │
                        │                      жёсткие оверлеи + списки) │
                        │                                ▼                │
                        │                     app.storage.db (SQLite,    │
                        │                     журнал/карантин/списки)    │
                        └───────────────┬───────────────────▲────────────┘
                                        │ REST              │ прокси
                        ┌───────────────▼───────────────────┴────────────┐
                        │ frontend (Next.js, route handlers = API-прокси)│
                        │  дашборд · карантин · списки · разбор .eml     │
                        └────────────────────────────────────────────────┘
```

Ключевые решения:

- **Модульный конвейер** (`backend/app`): каждый анализатор независим, отказ
  модуля не роняет анализ — его вес перераспределяется (`status=degraded`),
  а вердикт не «сползает» в безопасный.
- **Объяснимый скоринг**: итог = Σ(wᵢ·sᵢ)/Σ(wᵢ) по доступным модулям плюс
  жёсткие оверлеи (prompt-injection, исполняемое вложение, BEC-сочетания).
  Каждый сигнал виден на дашборде с весом и вкладом.
- **MTA без отдельного контейнера**: встроенный SMTP-фронт (RFC 5321,
  отвечает `550` на отклоняемые) и наблюдатель спула работают в lifespan
  бэкенда; режим задаётся `ANTISPAM_MTA_MODE`.
- **Безопасный прокси фронтенда**: ключи API/админа живут только на сервере
  Next.js (`GATEWAY_API_KEY`, `GATEWAY_ADMIN_TOKEN`), браузер обращается к
  собственным route handlers.
- **Безопасные дефолты**: пустой `ANTISPAM_API_KEYS` = API закрыт; ключи
  хранятся только хешами; `verify=False` не используется нигде.

## Быстрый старт (Docker)

```bash
cp .env.example .env          # задайте ключи API/админа
docker compose up --build     # backend:8000, frontend:3000
```

- Дашборд: http://localhost:3000
- Swagger бэкенда: http://localhost:8000/docs
- Данные (SQLite, карантин, спул) — в named volume `gateway-data`
  (`/app/data` в контейнере backend).

Подать письмо на проверку:

```bash
# через SMTP-фронт (если ANTISPAM_MTA_MODE=smtp)
swaks --to test@corp.ru --from security@sberbank-secure.top \
      --server localhost:2525 --body "Срочно подтвердите пароль"

# через спул (если ANTISPAM_MTA_MODE=watch): положите .eml в том
docker cp letter.eml phishing_backend:/app/data/spool/

# через REST
curl -X POST localhost:8000/api/v1/gateway/intercept \
  -H "X-API-Key: $ANTISPAM_API_KEYS" -H "Content-Type: application/json" \
  -d '{"sender":"a@evil.ru","recipient":"b@corp.ru","subject":"Срочно!",
       "body":"Подтвердите пароль по ссылке http://192.168.0.1/login"}'
```

## Локальная разработка

```bash
# backend (Python 3.11+)
cd backend
python -m venv venv && venv/Scripts/pip install -r requirements.txt   # Windows
# venv/bin/pip install -r requirements.txt                            # Linux/macOS
venv/Scripts/python -m pytest              # тесты (полностью офлайн)
venv/Scripts/uvicorn main:app --reload     # API на http://127.0.0.1:8000

# frontend (Node 20+)
cd frontend
npm install
npm run build        # проверка сборки/типов
npm run dev          # http://localhost:3000 (прокси → BACKEND_URL)
```

Для фронтенда задайте `BACKEND_URL` (по умолчанию `http://127.0.0.1:8000`)
и при необходимости `GATEWAY_API_KEY`, `GATEWAY_ADMIN_TOKEN`.

## REST API (основное)

| Метод   | Путь                                   | Доступ      | Описание                          |
|---------|----------------------------------------|-------------|-----------------------------------|
| GET     | `/health`                              | открыт      | состояние шлюза                   |
| POST    | `/api/v1/gateway/intercept`            | X-API-Key   | анализ структурированного письма  |
| POST    | `/api/v1/gateway/analyze/raw`          | X-API-Key   | анализ сырого письма (.eml)       |
| POST    | `/api/v1/gateway/mta-verify`           | ключ/MTA    | вердикт accept/tag/quarantine/reject |
| GET     | `/api/v1/stats`, `/api/v1/logs`        | X-API-Key   | статистика и журнал разборов      |
| GET     | `/api/v1/quarantine`                   | X-API-Key   | список карантина                  |
| POST    | `/api/v1/quarantine/{id}/release`      | +Admin      | выпуск письма из карантина        |
| POST    | `/api/v1/quarantine/{id}/reject`       | +Admin      | окончательный отказ               |
| GET/POST/DELETE | `/api/v1/lists`                | +Admin\*    | белые/чёрные списки               |
| GET     | `/api/v1/config`                        | X-API-Key   | снимок настроек (секреты скрыты)  |

\* чтение списков — по API-ключу, изменение — с X-Admin-Token.

## Переменные окружения

Полный пример — [`.env.example`](.env.example). Префикс `ANTISPAM_`
обрабатывается pydantic-settings (регистр не важен).

### Доступ и безопасность
| Переменная              | По умолчанию | Описание                                   |
|-------------------------|--------------|--------------------------------------------|
| `ANTISPAM_API_KEYS`     | *(пусто)*    | ключи REST API через запятую; пусто = API закрыт |
| `ANTISPAM_ADMIN_TOKEN`  | *(пусто)*    | токен административных действий            |
| `ANTISPAM_MTA_TOKEN`    | *(пусто)*    | секрет MTA для `mta-verify`                |
| `ANTISPAM_RATE_LIMIT_PER_IP` | `120`   | запросов в минуту на IP                    |
| `ANTISPAM_CORS_ORIGINS` | `*`          | разрешённые источники (через запятую)      |

### ИИ-модуль GigaChat
| Переменная               | По умолчанию      | Описание                              |
|--------------------------|-------------------|---------------------------------------|
| `GIGACHAT_AUTH_KEY`      | *(пусто)*         | base64 Basic-токен OAuth Sber         |
| `GIGACHAT_KEY_ADD`/`GIGACHAT_KEY_SECRET` | *(пусто)* | альтернативная пара ключей |
| `ANTISPAM_GIGACHAT_MODEL`| `GigaChat-2-Max`  | модель                                |
| `ANTISPAM_AI_ENABLED`    | `true`            | выключить — чисто эвристический режим |
| `ANTISPAM_GIGACHAT_TIMEOUT` / `RETRIES` / `CACHE_TTL` | `20`/`2`/`900` | сеть и кэш |

Без ключа ИИ шлюз работает на эвристике и честно сообщает `ai_configured=false`
в `/health` и `status=not_configured` в каждом вердикте.

### Вход почты (MTA)
| Переменная                  | По умолчанию          | Описание                     |
|-----------------------------|-----------------------|------------------------------|
| `ANTISPAM_MTA_MODE`         | `watch`               | `watch` \| `smtp` \| `disabled` |
| `ANTISPAM_MTA_SPOOL_DIR`    | `data/spool`          | каталог входящих `.eml`      |
| `ANTISPAM_MTA_PROCESSED_DIR`| `data/processed`      | обработанные письма          |
| `ANTISPAM_MTA_QUARANTINE_DIR`| `data/quarantine-eml`| отклонённые `.eml`           |
| `ANTISPAM_MTA_SMTP_PORT`    | `2525`                | порт SMTP-фронта             |
| `ANTISPAM_MTA_POLL_SECONDS` | `5`                   | период опроса спула          |

### Пороги и веса
| Переменная               | По умолчанию                                   |
|--------------------------|------------------------------------------------|
| `ANTISPAM_THRESHOLDS`    | `{"warn":35,"hold":55,"quarantine":70,"block":85}` |
| `ANTISPAM_MODULE_WEIGHTS`| `{"heuristics":0.22,"urls":0.26,"auth":0.22,"attachments":0.12,"ai":0.18}` |
| `ANTISPAM_GREY_ZONE`     | `8` (± от порога — пометка «на границе»)       |

### Внешние проверки ссылок
| Переменная                    | По умолчанию | Описание                             |
|-------------------------------|--------------|--------------------------------------|
| `ANTISPAM_RDAP_ENABLED`       | `true`       | возраст домена через RDAP (кэш 24 ч) |
| `ANTISPAM_DNS_CHECK_ENABLED`  | `true`       | разрешимость домена                  |
| `ANTISPAM_FOLLOW_REDIRECTS`   | `true`       | трассировка редиректов               |

### Хранилище
| Переменная                  | По умолчанию            |
|-----------------------------|-------------------------|
| `ANTISPAM_DB_PATH`          | `data/gateway.db`       |
| `ANTISPAM_QUARANTINE_TTL_DAYS` | `30`                 |
| `ANTISPAM_LOG_LEVEL` / `ANTISPAM_LOG_JSON` | `INFO` / `false` |

### Фронтенд
| Переменная            | По умолчанию             | Описание                     |
|-----------------------|--------------------------|------------------------------|
| `BACKEND_URL`         | `http://127.0.0.1:8000`  | адрес бэкенда для прокси     |
| `GATEWAY_API_KEY`     | *(пусто)*                | ключ, подставляемый прокси   |
| `GATEWAY_ADMIN_TOKEN` | *(пусто)*                | админ-токен прокси           |

## Интеграция с почтовым сервером

1. **SMTP-фронт** (`ANTISPAM_MTA_MODE=smtp`): настройте Postfix на доставку
   проверяемого трафика на `gateway:2525` (`relayhost` или transport-map).
   Отклоняемые письма получают `550 5.7.1` и не доходят до ящиков.
2. **Спул** (`watch`, по умолчанию): `getmail`/`fetchmail` или скрипт
   выгрузки кладёт `.eml` в `data/spool`; шлюз раскладывает их в
   `data/processed` или `data/quarantine-eml` и ведёт карантин в БД.
3. **REST-вердикт** для собственного милтера/плагина: `POST
   /api/v1/gateway/mta-verify` с `X-MTA-Token` возвращает `accept/tag/
   quarantine/reject` и заголовки `X-Phishing-*` для пометки письма.

## Тесты

```bash
cd backend && python -m pytest
```

84 теста, полностью офлайн (RDAP/DNS/редиректы/GigaChat отключены фикстурами):
эвристики, анализ URL, вложения, SPF/DKIM/DMARC, скоринг и оверлеи, парсер
`.eml`, REST API (аутентификация, лимиты, карантин, списки), наблюдатель
спула и SMTP-фронт (реальная SMTP-сессия на localhost).

## Структура репозитория

```
backend/
  main.py              REST-слой (FastAPI): транспорт, аутентификация, лимиты
  app/
    config.py          pydantic-settings: вся конфигурация из окружения
    schemas.py         pydantic-модели API и результатов
    analyzers/         heuristics, email_auth, url_intel, attachments,
                       email_parser, gigachat
    engine/            pipeline (конвейер), scoring (агрегация + оверлеи)
    mta/               smtp_server (SMTP-фронт), watcher (спул + режимы)
    security/          keys (хеши ключей), audit (журнал действий)
    storage/           db (SQLite: разборы/карантин/списки/статистика),
                       stores (белые/чёрные списки)
  tests/               pytest-набор (офлайн)
frontend/
  app/                 страницы дашборда + app/api/* (route handlers-прокси)
  components/          Nav, Badges, VerdictCard
  lib/                 backend.ts (прокси), types.ts
docker-compose.yml     backend + frontend, сеть gateway-net, том gateway-data
.env.example           все переменные окружения с комментариями
```
