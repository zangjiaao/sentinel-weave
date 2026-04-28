import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { getJson } from "@/lib/api"

function formatTime(value: string | null | undefined): string {
  if (!value) {
    return "-"
  }
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return value
  }
  return parsed.toLocaleString("zh-CN", { hour12: false })
}

export default async function ReportDetailPage({ params }: { params: Promise<{ reportId: string }> }) {
  const { reportId } = await params

  let data: any | null = null
  try {
    data = await getJson(`/api/reports/${reportId}`)
  } catch {
    data = null
  }

  if (!data?.report) {
    return (
      <section className="flex flex-col gap-4">
        <h1 className="text-2xl font-semibold">报告详情</h1>
        <Alert>
          <AlertTitle>无法加载报告</AlertTitle>
          <AlertDescription>报告不存在或 API 不可用。</AlertDescription>
        </Alert>
      </section>
    )
  }

  const item = data.report

  return (
    <section className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{item.report_id}</CardTitle>
          <CardDescription>{item.title || "-"}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Badge variant="outline">{item.status || "-"}</Badge>
          <Badge variant="outline">{item.case_id || "-"}</Badge>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>元数据</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableBody>
              <TableRow>
                <TableCell>created_at</TableCell>
                <TableCell>{formatTime(item.created_at)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>updated_at</TableCell>
                <TableCell>{formatTime(item.updated_at)}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>报告内容（Markdown）</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="whitespace-pre-wrap text-sm">{item.content_md || "-"}</pre>
        </CardContent>
      </Card>
    </section>
  )
}

