'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const LINKS = [
  { href: '/', label: 'Дашборд' },
  { href: '/quarantine', label: 'Карантин' },
  { href: '/lists', label: 'Списки' },
  { href: '/eml', label: 'Разбор .eml' },
];

export default function Nav() {
  const pathname = usePathname();

  return (
    <header className="border-b border-slate-800 bg-slate-950/80">
      <div className="max-w-7xl mx-auto px-6 py-3 flex flex-wrap items-center gap-x-8 gap-y-2">
        <Link href="/" className="font-bold tracking-tight text-cyan-400">
          🛡️ AI-Phishing Gateway
        </Link>
        <nav className="flex items-center gap-1 text-sm">
          {LINKS.map((link) => {
            const active = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`px-3 py-1.5 rounded-lg transition-colors ${
                  active
                    ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-900'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>
        <StatusDot />
      </div>
    </header>
  );
}

function StatusDot() {
  return (
    <div className="ml-auto text-xs text-slate-500">
      SOC-панель · <span className="text-emerald-400 font-semibold">● Online</span>
    </div>
  );
}
