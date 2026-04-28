import AlertsWorkbench from "@/components/alerts-workbench"

export default function AlertsPage() {
  return (
    <section className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold">告警（Alerts）</h1>
      <AlertsWorkbench />
    </section>
  )
}

