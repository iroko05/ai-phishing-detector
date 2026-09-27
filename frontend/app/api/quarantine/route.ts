import { proxyJson } from '@/lib/backend';
import type { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  return proxyJson({
    path: '/api/v1/quarantine',
    query: {
      status: params.get('status') ?? 'pending',
      limit: params.get('limit') ?? '50',
      offset: params.get('offset') ?? '0',
    },
  });
}
