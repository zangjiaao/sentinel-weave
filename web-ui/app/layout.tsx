import Link from "next/link";
import "./globals.css";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-CN">
      <body>
        <main className="container">
          <nav className="nav">
            <Link href="/alerts">告警</Link>
            <Link href="/cases">案件</Link>
            <Link href="/assets">资产</Link>
            <Link href="/notifications">通知</Link>
            <Link href="/reports">报告</Link>
          </nav>
          {children}
        </main>
      </body>
    </html>
  );
}
