import Link from "next/link"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { getJson } from "@/lib/api"

export default async function AssetsPage() {
  let items: any[] = []
  try {
    const response = await getJson("/api/assets")
    items = response.items || []
  } catch {
    items = []
  }

  return (
    <section className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold">资产</h1>
      {items.length === 0 ? (
        <Alert>
          <AlertTitle>暂无资产</AlertTitle>
          <AlertDescription>当前没有可展示的资产数据。</AlertDescription>
        </Alert>
      ) : null}
      {items.map((item) => (
        <Card key={item.asset_id}>
          <CardHeader>
            <CardTitle className="text-base">
              <Link href={`/assets/${item.asset_id}`} className="underline-offset-4 hover:underline">
                {item.asset_id}
              </Link>
            </CardTitle>
            <CardDescription>{item.asset_name || item.asset_id}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Badge variant="outline">{item.public_ip || "-"}</Badge>
            <Badge variant="outline">{item.domain || "-"}</Badge>
            <Badge variant="outline">{item.business_criticality || "unknown"}</Badge>
          </CardContent>
        </Card>
      ))}
    </section>
  )
}

