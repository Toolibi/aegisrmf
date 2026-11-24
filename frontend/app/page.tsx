"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useApi, useWorkspace } from "@/components/Workspace";
import { Empty, Legend, StatusBadge } from "@/components/Status";
import { Requirement, Score, STATUS_LABEL } from "@/lib/api";

const INDICATOR: Record<string, string> = {
  ALL_REQUIREMENTS_MET: "All 110 requirements met",
  CONDITIONAL_CRITERIA_MET: "Meets the criteria for a conditional POA&M",
  CONDITIONAL_CRITERIA_NOT_MET: "Does not meet the conditional POA&M criteria",
  INCOMPLETE_READINESS: "Readiness review still in progress",
  CANNOT_COMPLETE: "Assessment cannot be completed",
  INVALID_INPUT: "Results need correction",
};

export default function Overview() {
  const { current } = useWorkspace();
  const reqs = useApi<Requirement[]>(current ? `/v1/assessments/${current.id}/requirements` : null);
  const score = useApi<Score>(current && current.framework_id === "cmmc-l2" ? `/v1/assessments/${current.id}/score` : null);
  if (!current) return <Empty title="No assessment yet">Create one through the API or an MCP client, then reload this page.</Empty>;

  return (
    <div className="grid gap-8">
      <section aria-labelledby="matrix-h" className="grid gap-8 xl:grid-cols-[1fr_340px] items-start">
        <div className="rounded-lg border border-line bg-panel p-6">
          <div className="flex flex-wrap items-end justify-between gap-3 mb-5">
            <div>
              <h1 id="matrix-h" className="text-[26px] font-bold leading-tight">{current.system_name}</h1>
              <p className="text-steel mt-1">CMMC Level 2 against NIST SP 800-171 Rev. 2, all 110 requirements by family</p>
            </div>
            <Legend />
          </div>
          {reqs.error && <p role="alert" className="text-notmet">{reqs.error}</p>}
          {reqs.data ? <Matrix reqs={reqs.data} /> : <p className="text-steel">Loading requirements…</p>}
        </div>
        {score.data && <ScorePanel s={score.data} />}
      </section>
      {score.data && score.data.deductions.length > 0 && <Deductions s={score.data} />}
    </div>
  );
}

function Matrix({ reqs }: { reqs: Requirement[] }) {
  const families = useMemo(() => {
    const m = new Map<string, Requirement[]>();
    reqs.forEach((r) => m.set(r.family, [...(m.get(r.family) ?? []), r]));
    return [...m.entries()];
  }, [reqs]);
  const [hover, setHover] = useState<Requirement | null>(null);
  const counts = reqs.reduce<Record<string, number>>((a, r) => ({ ...a, [r.status]: (a[r.status] ?? 0) + 1 }), {});
  return (
    <div>
      <div className="grid gap-[7px]">
        {families.map(([fam, rs]) => (
          <div key={fam} className="grid grid-cols-1 sm:grid-cols-[190px_1fr] items-center gap-x-3 gap-y-1">
            <div className="text-sm text-steel truncate" title={rs[0].family_title}>{rs[0].family_title}</div>
            <div className="flex flex-wrap gap-[5px]">
              {rs.map((r) => (
                <Link key={r.key} href={`/requirements?r=${r.key}`}
                  onMouseEnter={() => setHover(r)} onFocus={() => setHover(r)}
                  aria-label={`${r.id} ${r.title}: ${STATUS_LABEL[r.status]}`}
                  className={`st-${r.status} block h-[26px] rounded-[4px] ${r.points === 5 ? "w-[34px]" : r.points === 3 ? "w-[24px]" : "w-[16px]"} ${r.links_proposed ? "outline-[1.5px] outline-dashed outline-ai outline-offset-[1.5px]" : ""}`} />
              ))}
            </div>
          </div>
        ))}
      </div>
      <p className="mt-5 text-sm text-steel leading-relaxed">
        Width shows the points a requirement can cost (5, 3 or 1). A dashed violet outline means AI-proposed evidence is waiting for review.
      </p>
      <div className="mt-4 min-h-[52px] rounded border border-line px-4 py-3 text-[15px]" aria-live="polite">
        {hover ? (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="font-semibold">{hover.id}</span><span>{hover.title}</span>
            <StatusBadge status={hover.status} />
            {hover.points !== null && <span className="text-steel">{hover.points} pt</span>}
          </div>
        ) : (
          <span className="text-steel">
            {counts.MET ?? 0} met, {counts.NOT_MET ?? 0} not met, {(counts.NOT_ASSESSED ?? 0) + (counts.INSUFFICIENT_EVIDENCE ?? 0)} still open. Point at a block for details.
          </span>
        )}
      </div>
    </div>
  );
}

function ScorePanel({ s }: { s: Score }) {
  return (
    <aside className="rounded-lg border border-line bg-panel p-6 grid gap-5">
      <div>
        <h2 className="text-steel text-[15px]">Readiness score</h2>
        <div className="mt-1 flex items-baseline gap-2">
          <span className={`text-[56px] font-bold leading-none ${s.score !== null && s.score < 0 ? "text-notmet" : "text-ink"}`}>{s.score ?? "—"}</span>
          <span className="text-steel text-lg">of {s.max_score}</span>
        </div>
        <p className="mt-3 font-semibold">{INDICATOR[s.indicator] ?? s.indicator}</p>
      </div>
      {s.blockers.length > 0 && (
        <div className="rounded border-l-4 border-notmet bg-[#fbeceb] px-3 py-2 text-[15px]">
          {s.blockers.map((b) => <p key={b}>{b}</p>)}
        </div>
      )}
      <dl className="grid grid-cols-2 gap-y-2 text-[15px]">
        <dt className="text-steel">Unresolved</dt><dd className="text-right">{s.unresolved.length} requirements</dd>
        <dt className="text-steel">Score ratio</dt><dd className="text-right">{s.poam_evaluation.score_ratio.toFixed(2)} (needs 0.80)</dd>
        <dt className="text-steel">Scoring rules</dt><dd className="text-right">{s.rules_version}</dd>
      </dl>
      {s.rules_review_status !== "APPROVED" && (
        <p className="text-sm text-insufficient">Scoring rules are awaiting sign-off by a qualified reviewer.</p>
      )}
      <p className="text-sm text-steel leading-relaxed border-t border-line pt-4">{s.disclaimer}</p>
    </aside>
  );
}

function Deductions({ s }: { s: Score }) {
  const [all, setAll] = useState(false);
  const rows = [...s.deductions].sort((a, b) => b.points - a.points);
  const shown = all ? rows : rows.slice(0, 8);
  return (
    <section aria-labelledby="ded-h" className="rounded-lg border border-line bg-panel p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="ded-h" className="text-xl font-bold">Where the points go</h2>
        <span className="text-sm text-steel">Input hash {s.input_hash.slice(0, 12)}… reproduces this score exactly</span>
      </div>
      <table className="mt-4 w-full text-[15px]">
        <thead><tr className="text-left text-steel border-b border-line">
          <th className="py-2 font-medium">Requirement</th><th className="font-medium">Status</th><th className="font-medium hidden sm:table-cell">Basis</th><th className="text-right font-medium">Points</th>
        </tr></thead>
        <tbody>
          {shown.map((d) => (
            <tr key={d.requirement} className="border-b border-line/70">
              <td className="py-2"><Link className="text-navy underline-offset-2 hover:underline" href={`/requirements?r=${d.requirement}`}>{d.requirement}</Link></td>
              <td>{STATUS_LABEL[d.status as keyof typeof STATUS_LABEL]}</td>
              <td className="text-steel hidden sm:table-cell">{d.basis}</td>
              <td className="text-right font-semibold text-notmet">−{d.points}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 8 && (
        <button onClick={() => setAll(!all)} className="mt-3 text-navy underline underline-offset-2">
          {all ? "Show the largest 8" : `Show all ${rows.length} deductions`}
        </button>
      )}
    </section>
  );
}
