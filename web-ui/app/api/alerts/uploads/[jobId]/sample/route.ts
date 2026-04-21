import { NextRequest, NextResponse } from "next/server";

const DEFAULT_BASE = "http://127.0.0.1:18080";

function apiBase(): string {
  return process.env.NEXT_PUBLIC_API_BASE || DEFAULT_BASE;
}

export async function GET(request: NextRequest, { params }: { params: { jobId: string } }) {
  const upstream = await fetch(
    `${apiBase()}/api/intake/uploads/${encodeURIComponent(params.jobId)}/sample?${request.nextUrl.searchParams.toString()}`,
    {
      method: "GET",
      cache: "no-store",
    },
  );
  const text = await upstream.text();
  return new NextResponse(text, {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") || "application/json",
    },
  });
}
