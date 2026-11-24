"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, Assessment, Config, loadConfig, Me, saveConfig } from "@/lib/api";

type Ctx = {
  ready: boolean;
  cfg: Config | null;
  me: Me | null;
  error: string | null;
  assessments: Assessment[];
  current: Assessment | null;
  select: (id: string) => void;
  connect: (c: Config) => Promise<void>;
  disconnect: () => void;
  refresh: () => void;
  version: number;
};

const WorkspaceContext = createContext<Ctx | null>(null);
const SEL = "aegisrmf.assessment";

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [cfg, setCfg] = useState<Config | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(null);
  const [version, setVersion] = useState(0);

  const load = useCallback(async (c: Config) => {
    const [who, list] = await Promise.all([api<Me>(c, "/v1/me"), api<Assessment[]>(c, "/v1/assessments")]);
    setMe(who);
    setAssessments(list);
    let stored: string | null = null;
    try { stored = window.localStorage.getItem(SEL); } catch {}
    setCurrentId(list.find((a) => a.id === stored)?.id ?? list[0]?.id ?? null);
  }, []);

  useEffect(() => {
    const c = loadConfig();
    if (!c) { setReady(true); return; }
    setCfg(c);
    load(c).catch((e) => setError(String(e.message ?? e))).finally(() => setReady(true));
  }, [load]);

  const connect = async (c: Config) => {
    setError(null);
    await load(c);
    saveConfig(c);
    setCfg(c);
  };
  const disconnect = () => { saveConfig(null); setCfg(null); setMe(null); setAssessments([]); };
  const select = (id: string) => {
    setCurrentId(id);
    try { window.localStorage.setItem(SEL, id); } catch {}
  };
  const refresh = () => {
    setVersion((v) => v + 1);
    if (cfg) load(cfg).catch((e) => setError(String(e.message ?? e)));
  };

  return (
    <WorkspaceContext.Provider value={{
      ready, cfg, me, error, assessments, current: assessments.find((a) => a.id === currentId) ?? null,
      select, connect, disconnect, refresh, version,
    }}>
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace() {
  const c = useContext(WorkspaceContext);
  if (!c) throw new Error("useWorkspace outside provider");
  return c;
}

/** Fetch helper bound to the workspace; re-runs when the assessment or refresh version changes. */
export function useApi<T>(path: string | null) {
  const { cfg, version } = useWorkspace();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!cfg || !path) return;
    let live = true;
    setLoading(true);
    api<T>(cfg, path)
      .then((d) => { if (live) { setData(d); setError(null); } })
      .catch((e) => { if (live) setError(String(e.message ?? e)); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [cfg, path, version]);
  return { data, error, loading };
}
