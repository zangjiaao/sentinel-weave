const DEFAULT_BASE = "http://127.0.0.1:18080"

function apiBase(): string {
  return process.env.NEXT_PUBLIC_API_BASE || DEFAULT_BASE
}

export async function getJson(path: string): Promise<any> {
  const response = await fetch(`${apiBase()}${path}`, {
    cache: "no-store",
  })
  if (!response.ok) {
    throw new Error(`request failed: ${response.status} ${path}`)
  }
  return response.json()
}

