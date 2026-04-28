import Link from "next/link"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { getJson } from "@/lib/api"

export default async function NotificationsPage() {
  let items: any[] = []
  try {
    const response = await getJson("/api/notifications")
    items = response.items || []
  } catch {
    items = []
  }

  return (
    <section className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold">通知</h1>
      <Alert>
        <AlertTitle>说明</AlertTitle>
        <AlertDescription>MVP 阶段仅展示通知记录，不执行真实发送。</AlertDescription>
      </Alert>
      {items.length === 0 ? (
        <Alert>
          <AlertTitle>暂无通知</AlertTitle>
          <AlertDescription>当前没有可展示的通知记录。</AlertDescription>
        </Alert>
      ) : null}
      {items.map((item) => (
        <Card key={item.notification_id}>
          <CardHeader>
            <CardTitle className="text-base">
              <Link href={`/notifications/${item.notification_id}`} className="underline-offset-4 hover:underline">
                {item.notification_id}
              </Link>
            </CardTitle>
            <CardDescription>{item.title || "-"}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Badge variant="outline">{item.channel || "-"}</Badge>
            <Badge variant="outline">{item.status || "-"}</Badge>
            <Badge variant="outline">{item.case_id || "-"}</Badge>
          </CardContent>
        </Card>
      ))}
    </section>
  )
}
