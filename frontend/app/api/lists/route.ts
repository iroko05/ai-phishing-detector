import { proxyJson } from '@/lib/backend';
import type { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const kind = request.nextUrl.searchParams.get('kind') ?? undefined;
  return proxyJson({ path: '/api/v1/lists', query: { kind } });
}

export async function POST(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const pattern = params.get('pattern')?.trim();
  if (!pattern) {
    return Response.json({ detail: 'Укажите домен, адрес или regex' }, { status: 400 });
  }
  return proxyJson({
    path: '/api/v1/lists',
    method: 'POST',
    admin: true,
    query: {
      pattern,
      kind: params.get('kind') ?? 'allow',
      note: params.get('note') ?? '',
    },
  });
}
