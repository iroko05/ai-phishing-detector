import { proxyJson } from '@/lib/backend';
import type { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  return proxyJson({
    path: '/api/v1/logs',
    query: {
      limit: params.get('limit') ?? '50',
      action: params.get('action') ?? undefined,
      min_score: params.get('min_score') ?? undefined,
    },
  });
}
