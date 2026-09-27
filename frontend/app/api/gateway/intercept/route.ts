import { proxyJson } from '@/lib/backend';
import type { NextRequest } from 'next/server';

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => null);
  if (!body) {
    return Response.json({ detail: 'Некорректный JSON' }, { status: 400 });
  }
  return proxyJson({ path: '/api/v1/gateway/intercept', method: 'POST', body });
}
