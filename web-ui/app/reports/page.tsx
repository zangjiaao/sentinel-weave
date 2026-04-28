import Link from "next/link"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { getJson } from "@/lib/api"

export default async function ReportsPage() {
  let items: any[] = []
  try {
    const response = await getJson("/api/reports")
    items = response.items || []
  } catch {
    items = []
  }

  return (
    <section className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold">报告</h1>
      <Alert>
        <AlertTitle>说明</AlertTitle>
        <AlertDescription>MVP 阶段仅展示报告记录，不执行真实导出。</AlertDescription>
      </Alert>
      {items.length === 0 ? (
        <Alert>
          <AlertTitle>暂无报告</AlertTitle>
          <AlertDescription>当前没有可展示的报告记录。</AlertDescription>
        </Alert>
      ) : null}
      {items.map((item) => (
        <Card key={item.report_id}>
          <CardHeader>
            <CardTitle className="text-base">
              <Link href={`/reports/${item.report_id}`} className="underline-offset-4 hover:underline">
                {item.report_id}
              </Link>
            </CardTitle>
            <CardDescription>{item.title || "-"}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Badge variant="outline">{item.status || "-"}</Badge>
            <Badge variant="outline">{item.case_id || "-"}</Badge>
            <Badge variant="outline">{item.tone || "-"}</Badge>
          </CardContent>
        </Card>
      ))}
    </section>
  )
}
