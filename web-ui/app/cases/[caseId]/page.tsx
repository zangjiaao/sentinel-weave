import { getJson } from "../../../lib/api";
import CaseDetailClient from "./CaseDetailClient";

export default async function CaseDetailPage({ params }: { params: { caseId: string } }) {
  let data: any | null = null;
  try {
    data = await getJson(`/api/cases/${params.caseId}`);
  } catch {
    data = null;
  }

  if (!data?.case) {
    return (
      <section>
        <h1 className="title">案件详情</h1>
        <p className="meta">案件不存在或 API 不可用</p>
      </section>
    );
  }

  return <CaseDetailClient data={data} />;
}
