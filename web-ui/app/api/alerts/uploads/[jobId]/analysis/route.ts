import { NextRequest, NextResponse } from "next/server"

const DEFAULT_BASE = "http://127.0.0.1:18080"

function apiBase(): string {
  return process.env.NEXT_PUBLIC_API_BASE || DEFAULT_BASE
}

export async function GET(_request: NextRequest, context: { params: Promise<{ jobId: string }> }) {
  const { jobId } = await context.params
  const upstream = await fetch(`${apiBase()}/api/intake/uploads/${encodeURIComponent(jobId)}/analysis`, {
    method: "GET",
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

