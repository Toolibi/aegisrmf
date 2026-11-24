"""Build the versioned CMMC Level 2 / Level 1 framework packages.

Source text: CMMC Assessment Guide - Level 2 v2.13 and NIST SP 800-171 Rev. 2 /
800-171A (June 2018). Both are U.S. Government works (public domain). The
machine-readable extraction used as input came from nealfennimore/cmmc at tag
1.0.0, which was released under the MIT License (later versions are ELv2 and
are NOT used). See NOTICE.md.

Point values are NOT taken from that repository; they live in
aegisrmf/scoring/rules/cmmc_l2_32cfr170_24.json, transcribed independently from
32 CFR 170.24. This script cross-checks the two and fails on any disagreement.

Usage: python tools/build_cmmc_catalog.py <assessment-guide-requirements.json> [scores.json]
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "aegisrmf"
OUT_L2 = ROOT / "catalog" / "data" / "cmmc-l2_ag-2.13_sp800-171r2.json"
OUT_L1 = ROOT / "catalog" / "data" / "cmmc-l1_far-52.204-21.json"
RULES = ROOT / "scoring" / "rules" / "cmmc_l2_32cfr170_24.json"

FAMILIES = {
    "AC": "Access Control", "AT": "Awareness and Training", "AU": "Audit and Accountability",
    "CM": "Configuration Management", "IA": "Identification and Authentication",
    "IR": "Incident Response", "MA": "Maintenance", "MP": "Media Protection",
    "PS": "Personnel Security", "PE": "Physical Protection", "RA": "Risk Assessment",
    "CA": "Security Assessment", "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# Evidence-type hints derived from the Examine/Interview/Test methods. These are
# planning aids only; they never decide a result.
def expected_evidence(methods: dict) -> list[str]:
    kinds = set()
    for item in methods.get("examine", []):
        low = item.lower()
        if "policy" in low or "procedure" in low:
            kinds.add("policy_procedure")
        if "plan" in low:
            kinds.add("plan")
        if "configuration" in low or "settings" in low:
            kinds.add("configuration")
        if "log" in low or "record" in low:
            kinds.add("records_logs")
        if "list" in low or "inventory" in low:
            kinds.add("inventory_list")
        if "training" in low:
            kinds.add("training_record")
        if "design" in low or "diagram" in low or "architecture" in low:
            kinds.add("architecture_diagram")
    if methods.get("test"):
        kinds.add("technical_test_result")
    if methods.get("interview"):
        kinds.add("interview_record")
    return sorted(kinds)


# FAR 52.204-21(b)(1) i..xv -> CMMC Level 2 requirement(s) whose objectives apply.
L1_MAP = [
    ("AC.L1-b.1.i", ["3.1.1"]), ("AC.L1-b.1.ii", ["3.1.2"]), ("AC.L1-b.1.iii", ["3.1.20"]),
    ("AC.L1-b.1.iv", ["3.1.22"]), ("IA.L1-b.1.v", ["3.5.1"]), ("IA.L1-b.1.vi", ["3.5.2"]),
    ("MP.L1-b.1.vii", ["3.8.3"]), ("PE.L1-b.1.viii", ["3.10.1"]),
    ("PE.L1-b.1.ix", ["3.10.3", "3.10.4", "3.10.5"]), ("SC.L1-b.1.x", ["3.13.1"]),
    ("SC.L1-b.1.xi", ["3.13.5"]), ("SI.L1-b.1.xii", ["3.14.1"]), ("SI.L1-b.1.xiii", ["3.14.2"]),
    ("SI.L1-b.1.xiv", ["3.14.4"]), ("SI.L1-b.1.xv", ["3.14.5"]),
]


def main(src: str, scores: str | None = None) -> None:
    raw = Path(src).read_bytes()
    data = json.loads(raw)
    reqs = data["requirements"]
    assert len(reqs) == 110, len(reqs)
    controls = []
    for r in reqs:
        fam = r["id"].split(".")[0]
        objs = [
            {"id": f"{r['nist_sp_800_171']}[{k}]", "letter": k, "text": v}
            for k, v in r["assessment_objectives"].items()
        ]
        controls.append({
            "id": r["id"],
            "nist_id": r["nist_sp_800_171"],
            "family": fam,
            "family_title": FAMILIES[fam],
            "title": r["name"],
            "statement": r["statement"],
            "assessment_objectives": objs,
            "assessment_procedures": r.get("assessment_methods", {}),
            "expected_evidence_types": expected_evidence(r.get("assessment_methods", {})),
            "references": r.get("key_references", []),
            "cross_framework_mappings": [
                {"framework": "nist-sp-800-171", "revision": "2", "id": r["nist_sp_800_171"],
                 "relationship": "source", "equivalence_asserted": True},
            ],
        })
    n_obj = sum(len(c["assessment_objectives"]) for c in controls)
    assert n_obj == 320, n_obj

    # Cross-check point values against independent rules file.
    rules = json.loads(RULES.read_text())
    values = rules["point_values"]
    assert set(values) == {c["nist_id"] for c in controls}, "rules/catalog id mismatch"
    if scores:
        ref = {s["identifier"]: s for s in json.loads(Path(scores).read_text())}
        bad = []
        for nid, v in values.items():
            key = "03." + ".".join(f"{int(p):02d}" for p in nid.split(".")[1:])
            ref_v = ref[key]["value"]
            mine = v if isinstance(v, int) else (v.get("max") if isinstance(v, dict) else 0)
            if v is None:
                mine = 0
            if mine != ref_v:
                bad.append((nid, mine, ref_v))
        if bad:
            raise SystemExit(f"Point-value disagreement with reference: {bad}")
        print("cross-check vs reference scores: 110/110 agree")

    pkg = {
        "framework_id": "cmmc-l2",
        "title": "CMMC Level 2",
        "revision": "Assessment Guide v2.13 / NIST SP 800-171 Rev. 2 / SP 800-171A (2018)",
        "package_version": "1.0.0",
        "authoritative_sources": [
            "32 CFR Part 170 (CMMC Program), effective 2024-12-16",
            "NIST SP 800-171 Rev. 2 (incorporated by reference in 32 CFR 170; Rev. 3 NOT applicable to CMMC)",
            "NIST SP 800-171A (June 2018)",
            "DoD CIO CMMC Assessment Guide - Level 2, v2.13",
        ],
        "effective_date": "2024-12-16",
        "notes": "Do not substitute SP 800-171 Rev. 3; 32 CFR 170 references Rev. 2.",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "controls": controls,
        "version_history": [{"package_version": "1.0.0", "change": "Initial package"}],
    }
    OUT_L2.write_text(json.dumps(pkg, indent=1, ensure_ascii=False))

    by_nist = {c["nist_id"]: c for c in controls}
    l1 = []
    for lid, targets in L1_MAP:
        objs = [o for t in targets for o in by_nist[t]["assessment_objectives"]]
        l1.append({
            "id": lid, "family": lid.split(".")[0], "title": " / ".join(by_nist[t]["title"] for t in targets),
            "statement": " ".join(by_nist[t]["statement"] for t in targets),
            "assessment_objectives": objs, "l2_equivalents": targets,
            "cross_framework_mappings": [{"framework": "cmmc-l2", "id": by_nist[t]["id"],
                                          "relationship": "objectives-reused", "equivalence_asserted": False}
                                         for t in targets],
        })
    OUT_L1.write_text(json.dumps({
        "framework_id": "cmmc-l1", "title": "CMMC Level 1", "revision": "FAR 52.204-21(b)(1)",
        "package_version": "1.0.0", "effective_date": "2024-12-16",
        "authoritative_sources": ["48 CFR 52.204-21", "32 CFR 170.15", "32 CFR 170.21(a)(1) - no POA&M at Level 1"],
        "controls": l1,
    }, indent=1, ensure_ascii=False))
    print(f"wrote {OUT_L2.name}: {len(controls)} requirements, {n_obj} objectives")
    print(f"wrote {OUT_L1.name}: {len(l1)} requirements")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
