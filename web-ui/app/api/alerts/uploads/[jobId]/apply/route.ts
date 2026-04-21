import { NextRequest, NextResponse } from "next/server";

const DEFAULT_BASE = "http://127.0.0.1:18080";

function apiBase(): string {
  return process.env.NEXT_PUBLIC_API_BASE || DEFAULT_BASE;
}

export async function POST(request: NextRequest, { params }: { params: { jobId: string } }) {
  const body = await request.json().catch(() => ({}));
  const payload = {
    limit: Number(body?.limit || 500),
    include_unmapped: body?.include_unmapped !== false,
    raw_event_ids: Array.isArray(body?.raw_event_ids) ? body.raw_event_ids : null,
    trigger_after_apply: body?.trigger_after_apply === true,
    trigger_dry_run: body?.trigger_dry_run === true,
  };

  const upstream = await fetch(`${apiBase()}/api/intake/uploads/${encodeURIComponent(params.jobId)}/apply-map`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  const text = await upstream.text();
  return new NextResponse(text, {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") || "application/json",
    },
  });
}
