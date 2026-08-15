"""Attribution validation corpus.

Fixtures in ``tests/fixtures/attribution/`` hold **observations only** — the
facts a scan collects — so each case runs the real pipeline (signature
matching, then interpretation) rather than pre-baked verdicts. A signature
change that quietly breaks attribution therefore fails here.

Every fixture is synthetic and sanitized: RFC 5737 documentation addresses
and example.* names, plus published vendor infrastructure (a Cloudflare
netblock, an Akamai CNAME suffix) which is what the signatures match on. No
private or proprietary target data lives in this repository.

The corpus is small on purpose. It is a regression and quality harness, not
a benchmark, and the summary it prints makes no statistical claim.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from w4f import attribution as ATT
from w4f.attribution import attribute
from w4f.scanner import detect_interception, fingerprint

FIXTURES = sorted((pathlib.Path(__file__).parent / "fixtures" / "attribution").glob("*.json"))
BAND_ORDER = {ATT.LOW: 0, ATT.MEDIUM: 1, ATT.HIGH: 2}


def _load(path: pathlib.Path) -> tuple[dict, dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["observations"], data["expected"]


def _run(observations: dict) -> dict:
    """The attribution-relevant part of probe_one, on stored observations."""
    result = dict(observations)
    result["verdict"] = fingerprint(result)
    icept = detect_interception(result.get("cert") or {})
    if icept:
        result["interception"] = icept
    return attribute(result)


def test_corpus_is_present():
    assert FIXTURES, "the attribution corpus is missing"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_fixture_attributes_as_expected(path):
    observations, expected = _load(path)
    att = _run(observations)

    assert att["state"] == expected["state"], (
        f"{path.stem}: expected {expected['state']}, got {att['state']} "
        f"(vendor={att.get('vendor')})")

    if expected.get("vendor") is None:
        assert att["vendor"] is None, \
            f"{path.stem}: no vendor should be attributed in {att['state']}"
    else:
        assert att["vendor"] == expected["vendor"], \
            f"{path.stem}: attributed {att['vendor']}, expected {expected['vendor']}"

    if expected.get("min_band"):
        assert BAND_ORDER[att["confidence"]] >= BAND_ORDER[expected["min_band"]]
    if expected.get("max_band"):
        assert BAND_ORDER[att["confidence"]] <= BAND_ORDER[expected["max_band"]]
    if expected.get("layers"):
        assert [ly["vendor"] for ly in att["layers"]] == expected["layers"]
        # a layer belongs to the stack; it must never also appear among the
        # competing edge candidates (a weaker EDGE vendor legitimately can)
        alt_names = {a["vendor"] for a in att["alternatives"]}
        assert not alt_names & set(expected["layers"]), \
            f"{path.stem}: a layer must not be listed as a competing edge"
        assert all(a["role"] == "edge" for a in att["alternatives"])


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_attributed_fixture_can_name_its_evidence(path):
    """Completion criterion: every attributed result identifies the evidence
    categories supporting it."""
    observations, _ = _load(path)
    att = _run(observations)
    if att["state"] != ATT.STATE_ATTRIBUTED:
        pytest.skip(f"{path.stem} is {att['state']}")
    assert att["basis"], f"{path.stem}: attributed with no basis"
    assert att["evidence"], f"{path.stem}: attributed with no evidence"
    assert {e["category"] for e in att["evidence"]} == set(att["basis"])


def corpus_quality() -> dict:
    """Tally the corpus by outcome. Regression measurement, not a benchmark.

    `incorrect` counts a confident answer that is wrong — the failure mode
    that matters most, since a wrong name is worse than no name.
    """
    tally = {"attributed_correct": 0, "ambiguous": 0, "unknown": 0,
             "intercepted": 0, "error": 0, "incorrect": 0}
    for path in FIXTURES:
        observations, expected = _load(path)
        att = _run(observations)
        state, want = att["state"], expected["state"]
        if state != want:
            tally["incorrect"] += 1
        elif state == ATT.STATE_ATTRIBUTED:
            if att["vendor"] == expected.get("vendor"):
                tally["attributed_correct"] += 1
            else:
                tally["incorrect"] += 1
        elif state == ATT.STATE_AMBIGUOUS:
            tally["ambiguous"] += 1
        elif state == ATT.STATE_UNKNOWN:
            tally["unknown"] += 1
        elif state == ATT.STATE_INTERCEPTED:
            tally["intercepted"] += 1
        elif state == ATT.STATE_ERROR:
            tally["error"] += 1
    return tally


def test_corpus_quality_has_no_incorrect_attributions(capsys):
    tally = corpus_quality()
    with capsys.disabled():
        print(f"\n  attribution corpus ({len(FIXTURES)} fixtures)")
        for key, count in tally.items():
            print(f"    {key:<20}{count}")
    assert tally["incorrect"] == 0, f"incorrect attributions: {tally}"
    # the corpus must keep exercising every state, or it stops being a
    # regression net for the ones that quietly disappear
    assert tally["attributed_correct"] >= 3
    assert tally["ambiguous"] >= 1
    assert tally["unknown"] >= 1
    assert tally["intercepted"] >= 1
    assert tally["error"] >= 1
