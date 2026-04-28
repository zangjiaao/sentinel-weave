import { Geist, Geist_Mono, Inter } from "next/font/google"
import Link from "next/link"

import "./globals.css"
import { ThemeProvider } from "@/components/theme-provider"
import { Button, buttonVariants } from "@/components/ui/button"
import { Toaster } from "@/components/ui/sonner"
import { cn } from "@/lib/utils"

const inter = Inter({subsets:['latin'],variable:'--font-sans'})

const fontMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
})

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={cn("antialiased", fontMono.variable, "font-sans", inter.variable)}
    >
      <body>
        <ThemeProvider>
          <main className="mx-auto flex w-full max-w-6xl flex-col gap-4 p-4">
            <nav className="flex items-center gap-2">
              <Link href="/alerts" className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}>
                告警
              </Link>
              <Link href="/cases" className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}>
                案件
              </Link>
              <Link href="/assets" className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}>
                资产
              </Link>
              <Link href="/notifications" className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}>
                通知
              </Link>
              <Link href="/reports" className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}>
                报告
              </Link>
            </nav>
            {children}
          </main>
          <Toaster />
        </ThemeProvider>
      </body>
    </html>
  )
}
