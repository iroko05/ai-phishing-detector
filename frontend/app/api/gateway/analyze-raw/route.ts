import { proxyJson } from '@/lib/backend';
import type { NextRequest } from 'next/server';

/** Разбор сырого письма (.eml): { raw_email: string, recipient?: string } */
export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body.raw_email !== 'string' || !body.raw_email.trim()) {
    return Response.json({ detail: 'Поле raw_email обязательно' }, { status: 400 });
  }
  return proxyJson({ path: '/api/v1/gateway/analyze/raw', method: 'POST', body });
}
