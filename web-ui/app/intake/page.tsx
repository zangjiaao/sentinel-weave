import { getJson } from "../../lib/api";

export default async function IntakePage() {
  let uploads: any[] = [];
  let sources: any[] = [];
  try {
    const [uploadResp, sourceResp] = await Promise.all([
      getJson("/api/intake/uploads"),
      getJson("/api/intake/sources"),
    ]);
    uploads = uploadResp.items || [];
    sources = sourceResp.items || [];
  } catch {
    uploads = [];
    sources = [];
  }

  return (
    <section>
      <h1 className="title">接入中心</h1>
      <div className="card">
        <h2>数据源</h2>
        {sources.length === 0 ? <p className="meta">暂无数据源</p> : null}
        {sources.map((item) => (
          <p key={item.source_id} className="meta">
            {item.source_name} · {item.source_mode} · {item.status}
          </p>
        ))}
      </div>
      <div className="card">
        <h2>上传任务</h2>
        {uploads.length === 0 ? <p className="meta">暂无上传任务</p> : null}
        {uploads.map((item) => (
          <p key={item.job_id} className="meta">
            {item.job_id} · {item.file_name} · {item.status}
          </p>
        ))}
      </div>
    </section>
  );
}

