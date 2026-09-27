import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Nav from "@/components/Nav";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AI-Phishing Gateway — SOC-панель",
  description:
    "Дашборд шлюза анализа корпоративной почты: статистика, карантин, списки отправителей и разбор писем .eml",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="ru"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-slate-950 text-slate-100">
        <Nav />
        <main className="flex-1">{children}</main>
        <footer className="border-t border-slate-800 py-3 text-center text-xs text-slate-600">
          AI-Phishing Gateway · SOC-панель мониторинга почтовых угроз
        </footer>
      </body>
    </html>
  );
}
