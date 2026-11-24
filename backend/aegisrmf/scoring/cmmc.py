"""Deterministic CMMC scoring engine (32 CFR 170.24 / 170.21).

Pure functions only: no database, no clock, no AI. Same inputs -> same output,
byte for byte. Every result carries an input hash and a human-readable trace so
an assessor can reproduce the number by hand.

This engine produces *indicators*. It never determines or implies CMMC
certification status; only a C3PAO / DCMA DIBCAC (or the OSA for a
self-assessment entered in SPRS) can do that.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path

ENGINE_VERSION = "1.0.0"
RULES_PATH = Path(__file__).parent / "rules" / "cmmc_l2_32cfr170_24.json"


class Status(str, Enum):
    MET = "MET"
    NOT_MET = "NOT_MET"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


UNRESOLVED = {Status.NOT_ASSESSED, Status.INSUFFICIENT_EVIDENCE}


class Mode(str, Enum):
    READINESS = "READINESS"  # internal, may be incomplete, conservative
    OFFICIAL = "OFFICIAL"    # every requirement must be determined


@dataclass(frozen=True)
class RequirementInput:
    nist_id: str
    status: Status
    partial_condition: str | None = None   # e.g. "mfa_remote_and_privileged_only"
    na_justification: str | None = None


@dataclass
class ScoreResult:
    mode: str
    score: int | None
    max_score: int
    deductions: list[dict]
    unresolved: list[str]
    blockers: list[str]
    poam_evaluation: dict
    indicator: str
    trace: list[str]
    input_hash: str
    rules_version: str
    engine_version: str
    rules_review_status: str
    disclaimer: str = (
        "Score indicator only. AegisRMF does not issue or infer CMMC certification or "
        "Conditional/Final status. Readiness results are internal and not a formal assessment."
    )
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@lru_cache(maxsize=1)
def load_rules(path: str = str(RULES_PATH)) -> dict:
    return json.loads(Path(path).read_text())


def derive_requirement_status(objective_statuses: list[Status]) -> Status:
    """Roll objective results up to a requirement (all objectives must be MET/N/A)."""
    if not objective_statuses:
        return Status.NOT_ASSESSED
    s = set(objective_statuses)
    if Status.NOT_MET in s:
        return Status.NOT_MET
    if s <= {Status.MET, Status.NOT_APPLICABLE}:
        return Status.NOT_APPLICABLE if s == {Status.NOT_APPLICABLE} else Status.MET
    if Status.INSUFFICIENT_EVIDENCE in s:
        return Status.INSUFFICIENT_EVIDENCE
    return Status.NOT_ASSESSED


def canonical_inputs(inputs: list[RequirementInput]) -> str:
    rows = sorted(
        ({"id": i.nist_id, "status": Status(i.status).value, "partial": i.partial_condition,
          "na": bool(i.na_justification)} for i in inputs),
        key=lambda r: [int(p) for p in r["id"].split(".")],
    )
    return json.dumps(rows, separators=(",", ":"), sort_keys=True)


def _value(rules: dict, nid: str, partial: str | None) -> tuple[int, str]:
    v = rules["point_values"][nid]
    if v is None:
        return 0, "not scored (SSP rule)"
    if isinstance(v, int):
        return v, f"{v} pt"
    if partial and partial == v["partial_condition"]:
        return v["partial"], f"{v['partial']} pt partial ({v['partial_condition_text']})"
    return v["max"], f"{v['max']} pt"


def score_level2(inputs: list[RequirementInput], mode: Mode = Mode.READINESS,
                 rules: dict | None = None) -> ScoreResult:
    rules = rules or load_rules()
    ids = set(rules["point_values"])
    errors: list[str] = []
    by_id: dict[str, RequirementInput] = {}
    for i in inputs:
        if i.nist_id not in ids:
            errors.append(f"unknown requirement {i.nist_id}")
            continue
        if i.nist_id in by_id:
            errors.append(f"duplicate requirement {i.nist_id}")
        by_id[i.nist_id] = i
        if Status(i.status) == Status.NOT_APPLICABLE and not (i.na_justification or "").strip():
            errors.append(f"{i.nist_id}: NOT_APPLICABLE requires a written justification")
        v = rules["point_values"][i.nist_id]
        if i.partial_condition and not (isinstance(v, dict) and v["partial_condition"] == i.partial_condition):
            errors.append(f"{i.nist_id}: partial condition '{i.partial_condition}' not permitted")
    # Missing requirements are treated as NOT_ASSESSED - never as MET.
    full = [by_id.get(n, RequirementInput(n, Status.NOT_ASSESSED)) for n in
            sorted(ids, key=lambda x: [int(p) for p in x.split(".")])]
    input_hash = hashlib.sha256(
        (rules["rules_version"] + "|" + canonical_inputs(full)).encode()).hexdigest()

    trace = [f"Start at maximum score {rules['max_score']} (32 CFR 170.24)."]
    deductions, unresolved, blockers = [], [], []
    score = rules["max_score"]
    ssp = rules["ssp_requirement"]
    for r in full:
        st = Status(r.status)
        if st in UNRESOLVED:
            unresolved.append(r.nist_id)
        if r.nist_id == ssp:
            if st != Status.MET:
                blockers.append(
                    f"{ssp} System Security Plan is {st.value}: assessment cannot be completed (32 CFR 170.24).")
            continue
        if st in (Status.MET, Status.NOT_APPLICABLE):
            continue
        # NOT_MET, or unresolved treated conservatively as NOT_MET in readiness mode
        pts, why = _value(rules, r.nist_id, r.partial_condition if st == Status.NOT_MET else None)
        score -= pts
        deductions.append({"requirement": r.nist_id, "status": st.value, "points": pts, "basis": why})
        trace.append(f"-{pts} {r.nist_id} {st.value} ({why}) -> {score}")

    if mode == Mode.OFFICIAL and unresolved:
        errors.append(f"OFFICIAL mode requires every requirement determined; {len(unresolved)} unresolved")

    poam = evaluate_poam_eligibility(full, score, rules)
    final_score: int | None = score
    if blockers:
        indicator = "CANNOT_COMPLETE"
        if mode == Mode.OFFICIAL:
            final_score = None
    elif errors:
        indicator = "INVALID_INPUT"
        if mode == Mode.OFFICIAL:
            final_score = None
    elif unresolved:
        indicator = "INCOMPLETE_READINESS"
    elif score == rules["max_score"]:
        indicator = "ALL_REQUIREMENTS_MET"
    elif poam["eligible"]:
        indicator = "CONDITIONAL_CRITERIA_MET"
    else:
        indicator = "CONDITIONAL_CRITERIA_NOT_MET"
    trace.append(f"Result: {final_score} / {rules['max_score']} indicator={indicator}")

    return ScoreResult(
        mode=mode.value, score=final_score, max_score=rules["max_score"], deductions=deductions,
        unresolved=unresolved, blockers=blockers, poam_evaluation=poam, indicator=indicator,
        trace=trace, input_hash=input_hash, rules_version=rules["rules_version"],
        engine_version=ENGINE_VERSION, rules_review_status=rules["review"]["status"], errors=errors,
    )


def evaluate_poam_eligibility(full: list[RequirementInput], score: int, rules: dict) -> dict:
    """32 CFR 170.21(a)(2): ratio >= 0.8, POA&M items <= 1 pt (3.13.11 partial excepted),
    and none of the never-on-POA&M requirements."""
    p = rules["poam"]
    ratio = score / rules["max_score"]
    reasons, items = [], []
    for r in full:
        st = Status(r.status)
        if st == Status.NOT_MET or st in UNRESOLVED:
            items.append(r.nist_id)
            if r.nist_id in p["never_on_poam"]:
                reasons.append(f"{r.nist_id} may never be on a POA&M")
                continue
            pts, _ = _value(rules, r.nist_id, r.partial_condition if st == Status.NOT_MET else None)
            exc = any(e["requirement"] == r.nist_id and e["condition"] == r.partial_condition
                      for e in p["exceptions"]) and st == Status.NOT_MET
            if pts > p["max_point_value_on_poam"] and not exc:
                reasons.append(f"{r.nist_id} is worth {pts} pts (> {p['max_point_value_on_poam']})")
    if ratio < p["min_score_ratio"]:
        reasons.append(f"score ratio {ratio:.3f} < {p['min_score_ratio']}")
    return {"eligible": not reasons, "score_ratio": round(ratio, 4), "poam_items": items,
            "reasons": reasons, "closeout_days": p["closeout_days"]}


def poam_permitted(nist_id: str, partial_condition: str | None = None, rules: dict | None = None) -> tuple[bool, str]:
    rules = rules or load_rules()
    p = rules["poam"]
    if nist_id in p["never_on_poam"]:
        return False, "never permitted on a POA&M (32 CFR 170.21(a)(2)(iv))"
    pts, _ = _value(rules, nist_id, partial_condition)
    if pts > p["max_point_value_on_poam"] and not any(
            e["requirement"] == nist_id and e["condition"] == partial_condition for e in p["exceptions"]):
        return False, f"point value {pts} exceeds 1 (32 CFR 170.21(a)(2)(iii))"
    return True, "permitted"


def score_level1(statuses: dict[str, Status], requirement_ids: list[str]) -> dict:
    """Level 1: all 15 FAR requirements must be MET (N/A counts as MET). No POA&M, no points."""
    missing = [r for r in requirement_ids if r not in statuses]
    not_met = [r for r, s in statuses.items() if Status(s) not in (Status.MET, Status.NOT_APPLICABLE)]
    return {"all_met": not missing and not not_met, "not_met_or_unresolved": sorted(not_met + missing),
            "poam_allowed": False, "basis": "32 CFR 170.15 / 170.21(a)(1)",
            "disclaimer": "Indicator only; not a CMMC status determination."}
