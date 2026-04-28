import Link from "next/link"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { getJson } from "@/lib/api"

export default async function AssetDetailPage({ params }: { params: Promise<{ assetId: string }> }) {
  const { assetId } = await params

  let detail: any | null = null
  let cases: any[] = []
  try {
    detail = await getJson(`/api/assets/${assetId}`)
  } catch {
    detail = null
  }
  try {
    const casesResponse = await getJson(`/api/assets/${assetId}/cases`)
    cases = casesResponse.items || []
  } catch {
    cases = []
  }

  if (!detail?.asset) {
    return (
      <section className="flex flex-col gap-4">
        <h1 className="text-2xl font-semibold">资产详情</h1>
        <Alert>
          <AlertTitle>无法加载资产</AlertTitle>
          <AlertDescription>资产不存在或 API 不可用。</AlertDescription>
        </Alert>
      </section>
    )
  }

  const asset = detail.asset

  return (
    <section className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{asset.asset_name || asset.asset_id}</CardTitle>
          <CardDescription>{asset.asset_id}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Badge variant="outline">{asset.public_ip || "-"}</Badge>
          <Badge variant="outline">{asset.domain || "-"}</Badge>
          <Badge variant="outline">{asset.hostname || "-"}</Badge>
          <Badge variant="outline">{asset.business_criticality || "unknown"}</Badge>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>关联案件</CardTitle>
          <CardDescription>该资产相关的案件列表。</CardDescription>
        </CardHeader>
        <CardContent>
          {cases.length === 0 ? (
            <Alert>
              <AlertDescription>暂无关联案件。</AlertDescription>
            </Alert>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>案件</TableHead>
                  <TableHead>标题</TableHead>
                  <TableHead>严重性</TableHead>
                  <TableHead>阶段</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cases.map((item) => (
                  <TableRow key={item.case_id}>
                    <TableCell>
                      <Link href={`/cases/${item.case_id}`} className="underline-offset-4 hover:underline">
                        {item.case_id}
                      </Link>
                    </TableCell>
                    <TableCell>{item.title || "-"}</TableCell>
                    <TableCell>{item.overall_severity || "-"}</TableCell>
                    <TableCell>{item.current_stage || "-"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </section>
  )
}

