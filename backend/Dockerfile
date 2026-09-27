# Бэкенд шлюза: REST API + встроенная MTA-интеграция (SMTP-фронт / спул)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Зависимости отдельным слоем для кэширования
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Исходный код (контекст сборки — backend/, см. backend/.dockerignore)
COPY main.py pytest.ini ./
COPY app ./app
COPY tests ./tests

# Непривилегированный пользователь + каталог данных (том)
RUN useradd --create-home --uid 10001 gateway \
    && mkdir -p /app/data \
    && chown -R gateway:gateway /app
USER gateway

# 8000 — REST API, 2525 — приёмный SMTP-фронт (ANTISPAM_MTA_MODE=smtp)
EXPOSE 8000 2525

# Healthcheck стандартной библиотекой (curl в slim-образе отсутствует)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]