"use client";

import { useApi, useWorkspace } from "@/components/Workspace";
import { Empty } from "@/components/Status";
import { Poam } from "@/lib/api";

const COLUMNS: { key: string[]; label: string }[] = [
  { key: ["DRAFT"], label: "Draft" },
  { key: ["OPEN", "IN_PROGRESS", "BLOCKED"], label: "Open" },
  { key: ["PENDING_VERIFICATION"], label: "Awaiting verification" },
  { key: ["CLOSED", "ACCEPTED_RISK"], label: "Closed or risk accepted" },
];

export default function PoamBoard() {
  const { current } = useWorkspace();
  const poams = useApi<Poam[]>(current ? `/v1/assessments/${current.id}/poams` : null);
  if (!current) return <Empty title="No assessment selected" />;
  const today = new Date().toISOString().slice(0, 10);
  return (
    <div className="grid gap-5">
      <header>
        <h1 className="text-[26px] font-bold">POA&amp;M</h1>
        <p className="mt-1 text-steel max-w-[72ch] leading-relaxed">
          Each item is checked against 32 CFR 170.21. Items marked not permitted must be fixed before a conditional status is possible; accepting the risk does not count as met.
        </p>
      </header>
      {poams.data && poams.data.length === 0 && <Empty title="No POA&M items">Generate them from requirements marked not met.</Empty>}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4 items-start">
        {COLUMNS.map((c) => {
          const items = (poams.data ?? []).filter((p) => c.key.includes(p.status));
          return (
            <section key={c.label} aria-label={c.label} className="rounded-lg bg-[#e9edf1] p-3">
              <h2 className="px-1 pb-2 font-semibold">{c.label} <span className="text-steel font-normal">{items.length}</span></h2>
              <ul className="grid gap-2">
                {items.map((p) => {
                  const overdue = p.scheduled_completion && p.scheduled_completion < today && !["CLOSED", "ACCEPTED_RISK"].includes(p.status);
                  return (
                    <li key={p.id} className="rounded bg-panel p-3 grid gap-1.5 border border-line">
                      <div className="flex justify-between gap-2 text-sm"><span className="font-semibold">{p.display_id}</span><span className="text-steel">{p.requirement_id}, {p.point_value} pt</span></div>
                      <p className="text-[15px] leading-snug">{p.weakness}</p>
                      <p className={`text-sm ${p.cmmc_poam_permitted ? "text-met" : "text-notmet font-semibold"}`}>
                        {p.cmmc_poam_permitted ? "Permitted on a CMMC POA&M" : `Not permitted: ${p.cmmc_poam_basis}`}
                      </p>
                      {p.status === "ACCEPTED_RISK" && <p className="text-sm text-insufficient">Risk accepted; still counted as not met</p>}
                      <p className="text-sm text-steel">{p.remediation_owner || "No owner yet"}{p.scheduled_completion ? `, due ${p.scheduled_completion}` : ""}{overdue ? " — overdue" : ""}</p>
                    </li>
                  );
                })}
              </ul>
            </section>
          );
        })}
      </div>
    </div>
  );
}
