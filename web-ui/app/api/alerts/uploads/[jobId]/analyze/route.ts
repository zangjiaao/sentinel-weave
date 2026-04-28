import { NextRequest, NextResponse } from "next/server"

const DEFAULT_BASE = "http://127.0.0.1:18080"

function apiBase(): string {
  return process.env.NEXT_PUBLIC_API_BASE || DEFAULT_BASE
}

export async function POST(request: NextRequest, context: { params: Promise<{ jobId: string }> }) {
  const { jobId } = await context.params
  const body = await request.json().catch(() => ({}))
  const payload = {
    dry_run: body?.dry_run === true,
  }
  const upstream = await fetch(`${apiBase()}/api/intake/uploads/${encodeURIComponent(jobId)}/trigger-analysis`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  })
  const text = await upstream.text()
  return new NextResponse(text, {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") || "application/json",
    },
  })
}

