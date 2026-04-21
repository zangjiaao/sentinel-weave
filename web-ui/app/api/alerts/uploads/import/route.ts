import { NextRequest, NextResponse } from "next/server";

const DEFAULT_BASE = "http://127.0.0.1:18080";

function apiBase(): string {
  return process.env.NEXT_PUBLIC_API_BASE || DEFAULT_BASE;
}

export async function POST(request: NextRequest) {
  const incoming = await request.formData();
  const upstreamBody = new FormData();
  for (const [key, value] of incoming.entries()) {
    upstreamBody.append(key, value);
  }

  if (!upstreamBody.has("apply_after_import")) {
    upstreamBody.append("apply_after_import", "false");
  }
  if (!upstreamBody.has("trigger_after_apply")) {
    upstreamBody.append("trigger_after_apply", "false");
  }
  if (!upstreamBody.has("trigger_dry_run")) {
    upstreamBody.append("trigger_dry_run", "false");
  }
  if (!upstreamBody.has("limit")) {
    upstreamBody.append("limit", "500");
  }

  const upstream = await fetch(`${apiBase()}/api/intake/uploads/import`, {
    method: "POST",
    body: upstreamBody,
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
