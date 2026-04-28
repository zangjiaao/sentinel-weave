import Link from "next/link"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { getJson } from "@/lib/api"

export default async function CasesPage() {
  let items: any[] = []
  try {
    const response = await getJson("/api/cases")
    items = response.items || []
  } catch {
    items = []
  }

  return (
    <section className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold">案件</h1>
      {items.length === 0 ? (
        <Alert>
          <AlertTitle>暂无案件</AlertTitle>
          <AlertDescription>当前没有可展示的案件数据。</AlertDescription>
        </Alert>
      ) : null}
      {items.map((item) => (
        <Card key={item.case_id}>
          <CardHeader>
            <CardTitle className="text-base">
              <Link href={`/cases/${item.case_id}`} className="underline-offset-4 hover:underline">
                {item.case_id}
              </Link>
            </CardTitle>
            <CardDescription>{item.title}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Badge variant="outline">{item.overall_severity}</Badge>
            <Badge variant="outline">{item.current_stage}</Badge>
            <Badge variant="outline">{item.status}</Badge>
          </CardContent>
        </Card>
      ))}
    </section>
  )
}

