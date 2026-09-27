/**
 * Прокси к REST-бэкенду шлюза (server-side only).
 *
 * Дашборд обращается только к собственным route handlers Next.js (/api/...),
 * а они уже проксируют запрос в FastAPI. Так ключи доступа не попадают
 * в браузер, а CORS не нужен вовсе.
 *
 * Переменные окружения (см. .env.example):
 *   BACKEND_URL          — адрес бэкенда (http://backend:8000 в Docker)
 *   GATEWAY_API_KEY      — X-API-Key для REST API
 *   GATEWAY_ADMIN_TOKEN  — X-Admin-Token для административных действий
 */

const BACKEND_URL = (process.env.BACKEND_URL ?? 'http://127.0.0.1:8000').replace(/\/+$/, '');

export interface BackendRequest {
  path: string;
  method?: 'GET' | 'POST' | 'DELETE';
  query?: Record<string, string | number | undefined>;
  body?: unknown;
  admin?: boolean;
}

export async function backendFetch(request: BackendRequest): Promise<Response> {
  const url = new URL(BACKEND_URL + request.path);
  for (const [key, value] of Object.entries(request.query ?? {})) {
    if (value !== undefined && value !== '') {
      url.searchParams.set(key, String(value));
    }
  }

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const apiKey = process.env.GATEWAY_API_KEY ?? '';
  if (apiKey) headers['X-API-Key'] = apiKey;
  if (request.admin) {
    const adminToken = process.env.GATEWAY_ADMIN_TOKEN ?? '';
    if (adminToken) headers['X-Admin-Token'] = adminToken;
  }

  return fetch(url.toString(), {
    method: request.method ?? 'GET',
    headers,
    body: request.body !== undefined ? JSON.stringify(request.body) : undefined,
    cache: 'no-store',
  });
}

/** Проксирует ответ бэкенда в ответ Next.js с сохранением статуса. */
export async function proxyJson(request: BackendRequest): Promise<Response> {
  try {
    const upstream = await backendFetch(request);
    const payload = await upstream.text();
    return new Response(payload, {
      status: upstream.status,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  } catch {
    return Response.json(
      { detail: 'Бэкенд шлюза недоступен — проверьте, что сервис запущен' },
      { status: 502 },
    );
  }
}
