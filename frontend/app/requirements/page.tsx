"use client";

import { Suspense, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useApi, useWorkspace } from "@/components/Workspace";
import { AiLabel, Empty, StatusBadge } from "@/components/Status";
import { Finding, Link as EvLink, Requirement, Status } from "@/lib/api";

export default function Page() {
  return <Suspense fallback={<p className="text-steel">Loading…</p>}><Requirements /></Suspense>;
}

function Requirements() {
  const { current } = useWorkspace();
  const params = useSearchParams();
  const router = useRouter();
  const selected = params.get("r");
  const [family, setFamily] = useState("ALL");
  const [status, setStatus] = useState<"ALL" | Status>("ALL");
  const reqs = useApi<Requirement[]>(current ? `/v1/assessments/${current.id}/requirements` : null);
  const families = useMemo(() => [...new Map((reqs.data ?? []).map((r) => [r.family, r.family_title])).entries()], [reqs.data]);
  if (!current) return <Empty title="No assessment selected" />;
  const list = (reqs.data ?? []).filter((r) => (family === "ALL" || r.family === family) && (status === "ALL" || r.status === status));
  const sel = reqs.data?.find((r) => r.key === selected) ?? null;

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,380px)_1fr] items-start">
      <section aria-label="Requirement list" className="rounded-lg border border-line bg-panel">
        <div className="flex flex-wrap gap-2 p-4 border-b border-line">
          <select aria-label="Family" value={family} onChange={(e) => setFamily(e.target.value)} className="rounded border border-line px-2 py-1.5 text-[15px]">
            <option value="ALL">All families</option>
            {families.map(([f, t]) => <option key={f} value={f}>{t}</option>)}
          </select>
          <select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value as Status | "ALL")} className="rounded border border-line px-2 py-1.5 text-[15px]">
            <option value="ALL">Any status</option>
            <option value="NOT_MET">Not met</option><option value="INSUFFICIENT_EVIDENCE">Insufficient evidence</option>
            <option value="NOT_ASSESSED">Not assessed</option><option value="MET">Met</option><option value="NOT_APPLICABLE">Not applicable</option>
          </select>
        </div>
        <ul className="max-h-[70vh] overflow-y-auto">
          {list.map((r) => (
            <li key={r.key}>
              <button onClick={() => router.replace(`/requirements?r=${r.key}`, { scroll: false })}
                aria-current={r.key === selected ? "true" : undefined}
                className={`w-full text-left px-4 py-3 border-b border-line/70 grid gap-1 ${r.key === selected ? "bg-navy-soft" : "hover:bg-paper"}`}>
                <span className="flex items-center justify-between gap-2">
                  <span className="font-semibold">{r.id}</span><StatusBadge status={r.status} />
                </span>
                <span className="text-[15px] text-steel">{r.title}</span>
                {r.links_proposed > 0 && <span className="text-[13px] text-ai">{r.links_proposed} proposed evidence link{r.links_proposed > 1 ? "s" : ""} to review</span>}
              </button>
            </li>
          ))}
          {reqs.data && list.length === 0 && <li className="p-4 text-steel">No requirements match these filters.</li>}
        </ul>
      </section>
      {sel ? <Detail r={sel} assessmentId={current.id} /> : <Empty title="Choose a requirement">Its objectives, evidence and AI suggestions appear here.</Empty>}
    </div>
  );
}

function Detail({ r, assessmentId }: { r: Requirement; assessmentId: string }) {
  const findings = useApi<Finding[]>(`/v1/assessments/${assessmentId}/findings?requirement_id=${r.key}`);
  const links = useApi<EvLink[]>(`/v1/assessments/${assessmentId}/evidence-links`);
  const mine = (links.data ?? []).filter((l) => l.requirement_id === r.key);
  return (
    <article className="rounded-lg border border-line bg-panel p-6 grid gap-6">
      <header>
        <div className="flex flex-wrap items-center gap-3"><h1 className="text-[24px] font-bold">{r.id}</h1><StatusBadge status={r.status} />
          {r.points !== null && <span className="text-steel">{r.points} pt if not met{r.partial_condition ? " (partial credit recorded)" : ""}</span>}
          {r.points === null && <span className="text-steel">Not scored; the assessment cannot be completed without it</span>}
        </div>
        <p className="mt-1 text-lg">{r.title}</p>
        <p className="mt-3 max-w-[72ch] text-steel leading-relaxed">{r.statement}</p>
      </header>

      <section aria-labelledby="obj-h">
        <h2 id="obj-h" className="font-bold mb-2">Assessment objectives</h2>
        <ol className="grid gap-2">
          {r.objectives.map((o) => {
            const f = findings.data?.find((x) => x.objective_id === o.id);
            return (
              <li key={o.id} className="grid gap-2 rounded border border-line p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <p className="max-w-[64ch]"><span className="font-semibold">{o.id}</span> {o.text}</p>
                  <StatusBadge status={o.status} />
                </div>
                {f && f.proposed_status !== "NOT_ASSESSED" && (
                  <div className="ai-fence rounded px-3 py-2 text-[15px]">
                    <AiLabel /> <span className="ml-1">suggests {f.proposed_status.replaceAll("_", " ").toLowerCase()}</span>
                    {f.qa_warnings.map((w) => <p key={w} className="mt-1 text-steel">{w}</p>)}
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      </section>

      <section aria-labelledby="ev-h">
        <h2 id="ev-h" className="font-bold mb-2">Evidence citations</h2>
        {mine.length === 0 ? <p className="text-steel">No evidence linked yet. Missing evidence stays missing.</p> : (
          <ul className="grid gap-2">
            {mine.map((l) => (
              <li key={l.id} className={`rounded p-3 text-[15px] ${l.status === "ACCEPTED" ? "border border-met/50 bg-[#eef6f1]" : l.status === "REJECTED" ? "border border-line opacity-60" : "ai-fence"}`}>
                <div className="flex flex-wrap justify-between gap-2">
                  <span><span className="font-semibold">{l.objective_id}</span> in {l.citation.filename} v{l.citation.version}, {l.citation.page ? `page ${l.citation.page}, ` : ""}line {l.citation.line}</span>
                  <span className={l.status === "PROPOSED" ? "text-ai font-semibold" : "text-steel"}>{l.status === "PROPOSED" ? "Proposed by AI" : l.status === "ACCEPTED" ? "Accepted by reviewer" : "Rejected"}</span>
                </div>
                <blockquote className="mt-1.5 border-l-2 border-line pl-3 italic">{l.citation.quote}</blockquote>
                <p className="mt-1 text-[13px] text-steel">{l.citation.evidence_kind}, sha256 {l.citation.sha256.slice(0, 16)}…</p>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="impl-h">
        <h2 id="impl-h" className="font-bold mb-2">Implementation statement</h2>
        <p className={r.implementation_statement ? "max-w-[72ch]" : "text-steel"}>{r.implementation_statement ?? "Not provided. The SSP draft will show this gap."}</p>
      </section>
    </article>
  );
}
