import { proxyJson } from '@/lib/backend';
import type { NextRequest } from 'next/server';

/** Административное действие над записью карантина: release | reject. */
export async function POST(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string; action: string }> },
) {
  const { id, action } = await params;
  if (!/^\d+$/.test(id) || !['release', 'reject'].includes(action)) {
    return Response.json({ detail: 'Некорректный запрос' }, { status: 400 });
  }
  return proxyJson({
    path: `/api/v1/quarantine/${id}/${action}`,
    method: 'POST',
    admin: true,
  });
}
