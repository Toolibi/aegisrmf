"use client";

import { useApi, useWorkspace } from "@/components/Workspace";

type Verify = { valid: boolean; events: number; head?: string; broken_at_seq?: number };

export default function Audit() {
  const { cfg } = useWorkspace();
  const v = useApi<Verify>(cfg ? "/v1/audit/verify" : null);
  return (
    <div className="grid gap-5 max-w-[760px]">
      <h1 className="text-[26px] font-bold">Audit trail</h1>
      <p className="text-steel leading-relaxed">
        Every change made through the dashboard, the API or an AI agent is written to a hash-chained log. Each entry includes the hash of the one before it, so editing or deleting any record breaks the chain.
      </p>
      {v.error && <p role="alert" className="text-notmet">{v.error}</p>}
      {v.data && (
        <div className={`rounded-lg border p-6 ${v.data.valid ? "border-met/50 bg-[#eef6f1]" : "border-notmet bg-[#fbeceb]"}`}>
          <p className="text-xl font-bold">{v.data.valid ? "Chain intact" : `Chain broken at entry ${v.data.broken_at_seq}`}</p>
          <p className="mt-1">{v.data.events} recorded events{v.data.head ? <>, latest hash <span className="break-all">{v.data.head.slice(0, 24)}…</span></> : null}</p>
        </div>
      )}
    </div>
  );
}
