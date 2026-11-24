"use client";

import { useState } from "react";
import { useWorkspace } from "./Workspace";

export function ConnectForm() {
  const { connect } = useWorkspace();
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:8000");
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <form className="grid gap-4 rounded-lg border border-line bg-panel p-5" onSubmit={async (e) => {
      e.preventDefault();
      setBusy(true); setErr(null);
      try { await connect({ baseUrl, apiKey }); }
      catch (x) { setErr(x instanceof Error ? `${x.message}. Check the API address and key.` : "Connection failed"); }
      finally { setBusy(false); }
    }}>
      <label className="grid gap-1.5 text-sm text-steel">API address
        <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} required
          className="rounded border border-line px-3 py-2 text-[15px] text-ink" />
      </label>
      <label className="grid gap-1.5 text-sm text-steel">API key
        <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} required type="password" autoComplete="off"
          placeholder="aeg_…" className="rounded border border-line px-3 py-2 text-[15px] text-ink" />
      </label>
      {err && <p role="alert" className="text-sm text-notmet">{err}</p>}
      <button disabled={busy} className="rounded bg-navy px-4 py-2.5 font-semibold text-white disabled:opacity-60">
        {busy ? "Connecting…" : "Connect"}
      </button>
    </form>
  );
}
