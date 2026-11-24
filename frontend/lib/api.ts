"use client";

export type Config = { baseUrl: string; apiKey: string };
const KEY = "aegisrmf.config";

export function loadConfig(): Config | null {
  try {
    const raw = window.localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Config) : null;
  } catch {
    return null;
  }
}

export function saveConfig(c: Config | null) {
  try {
    if (c) window.localStorage.setItem(KEY, JSON.stringify(c));
    else window.localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: config lives for this page only */
  }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T>(cfg: Config, path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(cfg.baseUrl.replace(/\/$/, "") + path, {
    ...init,
    headers: { Authorization: `Bearer ${cfg.apiKey}`, "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {}
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return res.json() as Promise<T>;
}

export type Status = "MET" | "NOT_MET" | "NOT_APPLICABLE" | "NOT_ASSESSED" | "INSUFFICIENT_EVIDENCE";

export const STATUS_LABEL: Record<Status, string> = {
  MET: "Met",
  NOT_MET: "Not met",
  NOT_APPLICABLE: "Not applicable",
  NOT_ASSESSED: "Not assessed",
  INSUFFICIENT_EVIDENCE: "Insufficient evidence",
};

export type Me = { tenant: string; user: string; role: string; scopes: string[] };
export type Assessment = {
  id: string; title: string; status: string; revision: number; kind: string;
  framework_id: string; framework_version: string; system_name: string;
};
export type Requirement = {
  id: string; key: string; family: string; family_title: string; title: string; statement: string;
  status: Status; points: number | null; partial_condition: string | null; implementation_statement: string | null;
  objectives: { id: string; text: string; status: Status }[];
  links_proposed: number; links_accepted: number; ai_suggestions: Record<string, number>;
};
export type Score = {
  mode: string; score: number | null; max_score: number; indicator: string; trace: string[];
  deductions: { requirement: string; status: string; points: number; basis: string }[];
  unresolved: string[]; blockers: string[]; disclaimer: string; input_hash: string;
  rules_version: string; rules_review_status: string;
  poam_evaluation: { eligible: boolean; score_ratio: number; reasons: string[]; poam_items: string[] };
};
export type Link = {
  id: string; objective_id: string; requirement_id: string; origin: string; status: string; confidence: number;
  analyzer: string; citation: { filename: string; version: number; sha256: string; page: number | null; line: number; quote: string; evidence_kind: string; rationale?: string };
};
export type Finding = { id: string; objective_id: string; requirement_id: string; proposed_status: Status; statement: string; qa_warnings: string[]; review_status: string };
export type Poam = {
  id: string; display_id: string; requirement_id: string; weakness: string; severity: string; point_value: number;
  cmmc_poam_permitted: boolean; cmmc_poam_basis: string; status: string; risk_owner: string; remediation_owner: string;
  corrective_action: string; scheduled_completion: string | null;
};
