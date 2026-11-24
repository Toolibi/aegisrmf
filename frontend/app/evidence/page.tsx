"use client";

import { useMemo, useState } from "react";
import { useApi, useWorkspace } from "@/components/Workspace";
import { AiLabel, Empty } from "@/components/Status";
import { api, Link as EvLink, Requirement } from "@/lib/api";

export default function EvidenceReview() {
  const { current, cfg, me, refresh } = useWorkspace();
  const links = useApi<EvLink[]>(current ? `/v1/assessments/${current.id}/evidence-links?status=PROPOSED` : null);
  const [done, setDone] = useState<Record<string, string>>({});
  const reqs = useApi<Requirement[]>(current ? `/v1/assessments/${current.id}/requirements` : null);
  const objText = useMemo(() => new Map((reqs.data ?? []).flatMap((r) => r.objectives.map((o) => [o.id, o.text] as const))), [reqs.data]);
  const [err, setErr] = useState<string | null>(null);
  const [limit, setLimit] = useState(12);
  // One card per cited evidence line; the objectives it may support are reviewed inside the card.
  const groups = useMemo(() => {
    const m = new Map<string, EvLink[]>();
    for (const l of links.data ?? []) {
      if (done[l.id]) continue;
      const k = `${l.citation.sha256}:${l.citation.page ?? ""}:${l.citation.line}`;
      m.set(k, [...(m.get(k) ?? []), l]);
    }
    return [...m.values()]
      .map((ls) => ls.sort((a, b) => b.confidence - a.confidence))
      .sort((a, b) => b[0].confidence - a[0].confidence);
  }, [links.data, done]);
  if (!current || !cfg) return <Empty title="No assessment selected" />;
  const canReview = me?.scopes.includes("findings:review") && me.role !== "agent";
  const pending = groups.flat();

  const decide = async (l: EvLink, decision: "ACCEPTED" | "REJECTED") => {
    setErr(null);
    try {
      await api(cfg, `/v1/evidence-links/${l.id}/review`, { method: "POST", body: JSON.stringify({ decision, comment: "Reviewed in dashboard" }) });
      setDone((d) => ({ ...d, [l.id]: decision }));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="grid gap-5 max-w-[920px]">
      <header>
        <h1 className="text-[26px] font-bold">Evidence review</h1>
        <p className="mt-1 text-steel max-w-[70ch] leading-relaxed">
          Each card is a link the analyzer proposed between an evidence line and an assessment objective. The quote was checked word for word against the stored file. Accept only links that actually support the objective.
        </p>
        {!canReview && <p className="mt-2 text-insufficient">Your role can view proposals but not accept or reject them.</p>}
        {err && <p role="alert" className="mt-2 text-notmet">{err}</p>}
      </header>
      {Object.keys(done).length > 0 && (
        <p className="text-steel">{Object.keys(done).length} reviewed this session. <button className="text-navy underline" onClick={() => { setDone({}); refresh(); }}>Refresh the list</button></p>
      )}
      {links.data && pending.length === 0 && <Empty title="Nothing waiting for review">Run evidence analysis on the assessment to get new proposals.</Empty>}
      {groups.length > 0 && (
        <p className="text-steel">{pending.length} proposed links on {groups.length} evidence lines, strongest first.</p>
      )}
      <ul className="grid gap-3">
        {groups.slice(0, limit).map((g) => {
          const c = g[0].citation;
          return (
            <li key={g[0].id} className="ai-fence rounded-lg p-4 grid gap-3">
              <div className="flex flex-wrap justify-between gap-2 text-[13px]">
                <span className="text-steel">{c.filename} v{c.version}, {c.page ? `page ${c.page}, ` : ""}line {c.line}, {c.evidence_kind}</span>
                <AiLabel>Proposed by {g[0].analyzer}</AiLabel>
              </div>
              <blockquote className="border-l-2 border-ai/40 pl-3 italic text-[16px] max-w-[72ch]">{c.quote}</blockquote>
              <ul className="grid gap-1.5">
                {g.map((l) => (
                  <li key={l.id} className="flex flex-wrap items-center justify-between gap-2 rounded bg-white/70 px-3 py-2">
                    <span className="min-w-0 max-w-[60ch]"><span className="font-semibold">{l.objective_id}</span> {objText.get(l.objective_id) ?? ""} <span className="text-steel text-sm whitespace-nowrap">({Math.round(l.confidence * 100)}%)</span></span>
                    {canReview && (
                      <span className="flex gap-2">
                        <button onClick={() => decide(l, "ACCEPTED")} className="rounded bg-met px-3 py-1 text-sm text-white font-semibold">Accept</button>
                        <button onClick={() => decide(l, "REJECTED")} className="rounded border border-line bg-white px-3 py-1 text-sm font-semibold">Reject</button>
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </li>
          );
        })}
      </ul>
      {groups.length > limit && (
        <button onClick={() => setLimit(limit + 12)} className="justify-self-start rounded border border-line bg-white px-4 py-2 font-semibold">
          Show 12 more evidence lines
        </button>
      )}
    </div>
  );
}
