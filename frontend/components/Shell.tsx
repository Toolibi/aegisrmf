"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useWorkspace } from "./Workspace";
import { ConnectForm } from "./ConnectForm";

const NAV = [
  { href: "/", label: "Assessment" },
  { href: "/requirements", label: "Requirements" },
  { href: "/evidence", label: "Evidence review" },
  { href: "/poam", label: "POA&M" },
  { href: "/audit", label: "Audit trail" },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const { ready, cfg, me, assessments, current, select, disconnect, error } = useWorkspace();
  const path = usePathname();

  if (!ready) return <div className="p-10 text-steel">Loading workspace…</div>;
  if (!cfg || !me) {
    return (
      <main className="min-h-screen grid place-items-center p-6">
        <div className="w-full max-w-md">
          <Brand />
          <p className="mt-6 mb-6 text-steel leading-relaxed">
            Connect to your AegisRMF API with a key issued for your organization. The key stays in this browser.
          </p>
          {error && <p role="alert" className="mb-4 text-notmet">{error}</p>}
          <ConnectForm />
        </div>
      </main>
    );
  }

  return (
    <div className="min-h-screen md:grid md:grid-cols-[232px_1fr]">
      <aside className="bg-ink text-white md:min-h-screen p-5 flex md:flex-col gap-6 md:gap-8 overflow-x-auto">
        <Brand light />
        <nav aria-label="Main" className="flex md:flex-col gap-1">
          {NAV.map((n) => {
            const active = n.href === "/" ? path === "/" : path.startsWith(n.href);
            return (
              <Link key={n.href} href={n.href} aria-current={active ? "page" : undefined}
                className={`whitespace-nowrap rounded px-3 py-2 text-[15px] ${active ? "bg-white/12 text-white font-semibold" : "text-white/70 hover:text-white"}`}>
                {n.label}
              </Link>
            );
          })}
        </nav>
        <div className="hidden md:block mt-auto text-sm text-white/60 leading-snug">
          <div className="text-white/90">{me.user}</div>
          <div>{me.tenant}</div>
          <div className="capitalize">{me.role}</div>
          <button onClick={disconnect} className="mt-3 underline underline-offset-2 hover:text-white">Disconnect</button>
        </div>
      </aside>
      <div className="min-w-0">
        <header className="border-b border-line bg-panel px-6 py-3 flex flex-wrap items-center gap-3">
          <label htmlFor="asmt" className="text-sm text-steel">Assessment</label>
          <select id="asmt" value={current?.id ?? ""} onChange={(e) => select(e.target.value)}
            className="min-w-0 max-w-full rounded border border-line bg-white px-2 py-1.5 text-[15px]">
            {assessments.length === 0 && <option value="">No assessments yet</option>}
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>{a.system_name} — {a.title} (rev {a.revision})</option>
            ))}
          </select>
          {current && <StatusPill status={current.status} />}
        </header>
        <main className="px-6 py-7 max-w-[1240px]">{children}</main>
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const finalized = status === "FINALIZED";
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-sm ${finalized ? "bg-navy text-white" : "bg-navy-soft text-navy"}`}>
      {finalized ? "Finalized record" : "Draft readiness review"}
    </span>
  );
}

function Brand({ light = false }: { light?: boolean }) {
  return (
    <div className={`flex items-center gap-2.5 ${light ? "text-white" : "text-ink"}`}>
      <svg width="26" height="26" viewBox="0 0 26 26" aria-hidden>
        <path d="M13 1 24 5v8c0 6-4.6 10.6-11 12C6.6 23.6 2 19 2 13V5z" fill={light ? "#fff" : "#1f4e79"} />
        <path d="m8 13 3.4 3.4L18.5 9" stroke={light ? "#1b2430" : "#fff"} strokeWidth="2.4" fill="none" strokeLinecap="round" />
      </svg>
      <span className="text-[19px] font-bold tracking-tight">AegisRMF</span>
    </div>
  );
}
