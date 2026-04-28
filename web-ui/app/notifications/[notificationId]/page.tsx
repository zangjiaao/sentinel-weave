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

export default async function NotificationDetailPage({ params }: { params: Promise<{ notificationId: string }> }) {
  const { notificationId } = await params

  let data: any | null = null
  try {
    data = await getJson(`/api/notifications/${notificationId}`)
  } catch {
    data = null
  }

  if (!data?.notification) {
    return (
      <section className="flex flex-col gap-4">
        <h1 className="text-2xl font-semibold">通知详情</h1>
        <Alert>
          <AlertTitle>无法加载通知</AlertTitle>
          <AlertDescription>通知不存在或 API 不可用。</AlertDescription>
        </Alert>
      </section>
    )
  }

  const item = data.notification

  return (
    <section className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{item.notification_id}</CardTitle>
          <CardDescription>{item.title || "-"}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Badge variant="outline">{item.channel || "-"}</Badge>
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
                <TableCell>template</TableCell>
                <TableCell>{item.template || "-"}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>dedupe_key</TableCell>
                <TableCell>{item.dedupe_key || "-"}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>created_at</TableCell>
                <TableCell>{formatTime(item.created_at)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>sent_at</TableCell>
                <TableCell>{formatTime(item.sent_at)}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>正文</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="whitespace-pre-wrap text-sm">{item.body || "-"}</pre>
        </CardContent>
      </Card>
    </section>
  )
}

