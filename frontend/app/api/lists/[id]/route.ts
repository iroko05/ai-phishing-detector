import { proxyJson } from '@/lib/backend';
import type { NextRequest } from 'next/server';

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  if (!/^\d+$/.test(id)) {
    return Response.json({ detail: 'Некорректный идентификатор' }, { status: 400 });
  }
  return proxyJson({ path: `/api/v1/lists/${id}`, method: 'DELETE', admin: true });
}
