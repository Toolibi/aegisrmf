import json
import random

import pytest
from conftest import FIX

from aegisrmf import catalog
from aegisrmf.scoring import cmmc
from aegisrmf.scoring.cmmc import Mode, RequirementInput as RI, Status as S

RULES = cmmc.load_rules()
IDS = list(RULES["point_values"])
CASES = json.loads((FIX / "expected" / "cmmc_l2_scoring_cases.json").read_text())["cases"]


def build(not_met: dict) -> list[RI]:
    return [RI(i, S.NOT_MET, not_met[i]) if i in not_met else RI(i, S.MET) for i in IDS]


def one_pointers(n):
    never = set(RULES["poam"]["never_on_poam"])
    ones = [i for i, v in RULES["point_values"].items() if v == 1 and i not in never]
    return {i: None for i in ones[:n]}


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_regulatory_fixtures(case):
    if case.get("all_not_met"):
        inputs = [RI(i, S.NOT_MET) for i in IDS]
    elif "not_met_one_pointers" in case:
        inputs = build(one_pointers(case["not_met_one_pointers"]))
    else:
        inputs = build(case["not_met"])
    r = cmmc.score_level2(inputs, Mode.READINESS)
    assert r.score == case["expect_score"], r.trace
    assert r.poam_evaluation["eligible"] is case["expect_poam_eligible"], r.poam_evaluation
    if "expect_indicator" in case:
        assert r.indicator == case["expect_indicator"]


def test_point_value_totals():
    vals = RULES["point_values"]
    assert len(vals) == 110
    assert sum(1 for v in vals.values() if v == 5) == 42
    assert sum(1 for v in vals.values() if v == 3) == 14
    assert sum(1 for v in vals.values() if v == 1) == 51
    assert vals["3.12.4"] is None
    assert vals["3.5.3"]["max"] == 5 and vals["3.5.3"]["partial"] == 3
    assert vals["3.13.11"]["max"] == 5 and vals["3.13.11"]["partial"] == 3


def test_ssp_missing_blocks_official_score():
    inputs = build({"3.12.4": None})
    off = cmmc.score_level2(inputs, Mode.OFFICIAL)
    assert off.score is None and off.indicator == "CANNOT_COMPLETE" and off.blockers
    ready = cmmc.score_level2(inputs, Mode.READINESS)
    assert ready.score == 110 and ready.indicator == "CANNOT_COMPLETE"  # SSP itself carries no points


def test_not_applicable_needs_justification_and_counts_as_met():
    inputs = [RI(i, S.MET) for i in IDS if i != "3.1.16"]
    bad = cmmc.score_level2(inputs + [RI("3.1.16", S.NOT_APPLICABLE)], Mode.OFFICIAL)
    assert bad.score is None and any("justification" in e for e in bad.errors)
    ok = cmmc.score_level2(inputs + [RI("3.1.16", S.NOT_APPLICABLE, na_justification="No wireless in enclave")],
                           Mode.OFFICIAL)
    assert ok.score == 110 and not ok.errors


def test_unresolved_is_conservative_and_blocks_official():
    inputs = build({})
    inputs = [RI("3.1.1", S.INSUFFICIENT_EVIDENCE) if r.nist_id == "3.1.1" else r for r in inputs]
    ready = cmmc.score_level2(inputs, Mode.READINESS)
    assert ready.score == 105 and ready.indicator == "INCOMPLETE_READINESS"
    off = cmmc.score_level2(inputs, Mode.OFFICIAL)
    assert off.errors and off.indicator == "INVALID_INPUT" and off.score is None


def test_missing_requirements_never_count_as_met():
    r = cmmc.score_level2([RI("3.1.1", S.MET)], Mode.READINESS)
    assert r.score == -203 + 5 and len(r.unresolved) == 109


def test_partial_condition_only_where_permitted():
    r = cmmc.score_level2(build({"3.1.1": "mfa_remote_and_privileged_only"}), Mode.OFFICIAL)
    assert r.errors and r.score is None


def test_reproducible_regardless_of_order():
    inputs = build({"3.1.1": None, "3.13.11": "encryption_not_fips_validated"})
    a = cmmc.score_level2(inputs)
    shuffled = inputs[:]
    random.Random(7).shuffle(shuffled)
    b = cmmc.score_level2(shuffled)
    assert a.to_dict() == b.to_dict()
    c = cmmc.score_level2(build({"3.1.1": None}))
    assert c.input_hash != a.input_hash


@pytest.mark.parametrize("objs,expected", [
    ([S.MET, S.MET], S.MET), ([S.MET, S.NOT_APPLICABLE], S.MET), ([S.NOT_APPLICABLE], S.NOT_APPLICABLE),
    ([S.MET, S.NOT_MET, S.NOT_ASSESSED], S.NOT_MET), ([S.MET, S.INSUFFICIENT_EVIDENCE], S.INSUFFICIENT_EVIDENCE),
    ([S.MET, S.NOT_ASSESSED], S.NOT_ASSESSED), ([], S.NOT_ASSESSED)])
def test_objective_rollup(objs, expected):
    assert cmmc.derive_requirement_status(objs) == expected


def test_level1_no_poam_all_must_be_met():
    ids = [c["id"] for c in catalog.load("cmmc-l1")["controls"]]
    assert len(ids) == 15
    ok = cmmc.score_level1({i: S.MET for i in ids}, ids)
    assert ok["all_met"] and ok["poam_allowed"] is False
    bad = cmmc.score_level1({**{i: S.MET for i in ids}, ids[0]: S.NOT_MET}, ids)
    assert not bad["all_met"]


def test_catalog_counts_and_rev2_pin():
    pkg = catalog.load("cmmc-l2")
    assert len(pkg["controls"]) == 110
    assert sum(len(c["assessment_objectives"]) for c in pkg["controls"]) == 320
    assert "Rev. 2" in pkg["revision"] and "Rev. 3 NOT applicable" in " ".join(pkg["authoritative_sources"])
    assert set(RULES["point_values"]) == set(pkg["_index"])
    for c in pkg["controls"]:
        for m in c["cross_framework_mappings"]:
            assert "equivalence_asserted" in m


def test_rules_require_human_review_flag():
    assert RULES["review"]["status"] in ("PENDING_HUMAN_REVIEW", "APPROVED")
    r = cmmc.score_level2(build({}))
    assert r.rules_review_status == RULES["review"]["status"]
    assert "does not issue or infer CMMC certification" in r.disclaimer
