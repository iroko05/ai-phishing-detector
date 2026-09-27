import { proxyJson } from '@/lib/backend';
import type { NextRequest } from 'next/server';

export async function GET(request: NextRequest) {
  const days = request.nextUrl.searchParams.get('days') ?? '7';
  return proxyJson({ path: '/api/v1/stats', query: { days } });
}
