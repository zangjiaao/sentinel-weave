import { getJson } from "../../lib/api";

export default async function NotificationsPage() {
  let items: any[] = [];
  try {
    const response = await getJson("/api/notifications");
    items = response.items || [];
  } catch {
    items = [];
  }

  return (
    <section>
      <h1 className="title">通知</h1>
      <div className="card">
        <p className="meta">MVP 仅支持预览，不执行真实发送。</p>
      </div>
      {items.length === 0 ? <p className="meta">暂无通知记录</p> : null}
      {items.map((item) => (
        <div key={item.notification_id} className="card">
          <p className="meta">{item.notification_id}</p>
          <p className="meta">
            {item.channel} · {item.status} · case={item.case_id}
          </p>
          <p className="meta">{item.title}</p>
        </div>
      ))}
    </section>
  );
}

