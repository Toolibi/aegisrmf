"""Versioned framework catalogs. Packages are immutable JSON files; a new revision is a new file."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).parent / "data"
PACKAGES = {
    ("cmmc-l2", "1.0.0"): "cmmc-l2_ag-2.13_sp800-171r2.json",
    ("cmmc-l1", "1.0.0"): "cmmc-l1_far-52.204-21.json",
}
DEFAULT_VERSION = {"cmmc-l2": "1.0.0", "cmmc-l1": "1.0.0"}


class UnknownFramework(KeyError):
    pass


@lru_cache(maxsize=None)
def load(framework_id: str, version: str | None = None) -> dict:
    version = version or DEFAULT_VERSION.get(framework_id)
    try:
        fname = PACKAGES[(framework_id, version)]
    except KeyError as e:
        raise UnknownFramework(f"{framework_id}@{version}") from e
    pkg = json.loads((DATA / fname).read_text())
    pkg["_index"] = {c.get("nist_id", c["id"]): c for c in pkg["controls"]}
    pkg["_objectives"] = {o["id"]: (c.get("nist_id", c["id"]), o)
                          for c in pkg["controls"] for o in c["assessment_objectives"]}
    return pkg


def list_frameworks() -> list[dict]:
    out = []
    for (fid, ver) in PACKAGES:
        p = load(fid, ver)
        out.append({"framework_id": fid, "package_version": ver, "title": p["title"],
                    "revision": p["revision"], "effective_date": p["effective_date"],
                    "requirements": len(p["controls"]),
                    "objectives": sum(len(c["assessment_objectives"]) for c in p["controls"])})
    return out


def requirement_key(control: dict) -> str:
    """Scoring key: NIST id for L2 (e.g. 3.1.1), FAR id for L1."""
    return control.get("nist_id", control["id"])
