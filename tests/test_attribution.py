"""Attribution model: observations -> evidence -> attribution -> state.

Covers each result state and the rendering that depends on it. The states
exist so that "no vendor name" does not collapse several very different
situations into one; most of these tests are about keeping them apart.
"""

from __future__ import annotations

from w4f import attribution as ATT
from w4f.attribution import (
    attribute,
    confidence_band,
    evidence_for,
    observations,
    role_of,
)
from w4f.report import fmt_block, fmt_compact_block, fmt_summary_table
from w4f.scanner import fingerprint


def _result(verdict=None, **kw):
    """A scanned host with whatever observations the case needs."""
    r = {
        "host": "api.example.com", "hostport": "api.example.com:443", "port": 443,
        "ips": kw.get("ips", ["104.18.1.79"]),
        "cname": kw.get("cname", []), "ptr": kw.get("ptr", []),
        "error": kw.get("error"),
        "chain_verified": True,
        "tls": {
            "tls_version": "TLSv1.3", "alpn": "h2", "mtls": False,
            "cert": kw.get("cert", {"issuer_org": "Example CA", "subject": "CN=x",
                                    "spki_sha256": "a" * 64, "days_remaining": 90}),
            "http": {"status": "HTTP/1.1 200 OK",
                     "headers": kw.get("headers", {}), "set-cookie-list": []},
        },
        "verdict": verdict if verdict is not None else [],
    }
    if kw.get("interception"):
        r["interception"] = kw["interception"]
    if kw.get("no_tls"):
        r["tls"] = {}
    return r


def _match(vendor, score, cats, deployment=None, items=None):
    m = {"vendor": vendor, "signals": len(cats), "confidence": score,
         "categories": list(cats), "evidence": [f"{c}: x" for c in cats],
         "evidence_items": items or [{"category": c, "detail": f"{c}-detail"}
                                     for c in cats]}
    if deployment:
        m["deployment"] = deployment
    return m


class TestConfidenceBands:
    def test_bands(self):
        assert confidence_band(92) == ATT.HIGH
        assert confidence_band(70) == ATT.HIGH
        assert confidence_band(69) == ATT.MEDIUM
        assert confidence_band(30) == ATT.MEDIUM
        assert confidence_band(29) == ATT.LOW
        assert confidence_band(7) == ATT.LOW
        assert confidence_band(None) is None

    def test_high_needs_more_than_one_category(self):
        # the strongest single category is netblock (30) — HIGH must mean
        # several independent kinds of evidence agreed
        from w4f.scanner import CONF_WEIGHTS
        assert max(CONF_WEIGHTS.values()) < ATT.HIGH_AT


class TestStrongAttribution:
    def test_multi_category_match_is_attributed(self):
        r = _result([_match("cloudflare", 82, ["netblock", "cert", "cname", "headers"],
                            "cloud")])
        att = attribute(r)
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "cloudflare"
        assert att["score"] == 82
        assert att["confidence"] == ATT.HIGH
        assert att["basis"] == ["netblock", "cert", "cname", "headers"]
        assert att["role"] == "edge"
        assert att["deployment"] == "cloud"

    def test_every_attribution_identifies_its_evidence(self):
        # completion criterion: a non-unknown attribution can always say
        # which evidence categories support it
        r = _result([_match("cloudflare", 82, ["netblock", "cert"])])
        att = attribute(r)
        assert att["evidence"]
        assert {e["category"] for e in att["evidence"]} == {"netblock", "cert"}
        assert [e["label"] for e in att["evidence"]] == ["Network", "Certificate"]

    def test_origin_is_a_layer_not_an_alternative(self):
        # an origin under the edge belongs to the stack, not to the list of
        # competing edge candidates
        r = _result([_match("imperva", 60, ["netblock", "headers"]),
                     _match("nginx", 7, ["headers"], "origin")])
        att = attribute(r)
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "imperva"
        assert att["alternatives"] == []
        assert [ly["vendor"] for ly in att["layers"]] == ["nginx"]
        assert att["layers"][0]["role"] == "origin"

    def test_weaker_edge_stays_an_alternative(self):
        r = _result([_match("cloudflare", 82, ["netblock", "cert", "cname"]),
                     _match("aws-cloudfront", 25, ["cert"])])
        att = attribute(r)
        assert [a["vendor"] for a in att["alternatives"]] == ["aws-cloudfront"]
        assert att["layers"] == []


class TestWeakAttribution:
    def test_single_header_category_is_low(self):
        r = _result([_match("nginx", 7, ["headers"], "origin")])
        att = attribute(r)
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["confidence"] == ATT.LOW
        assert att["basis"] == ["headers"]

    def test_low_confidence_still_names_its_basis(self):
        att = attribute(_result([_match("kong", 7, ["headers"])]))
        assert att["evidence"][0]["label"] == "HTTP"


class TestAmbiguous:
    def _ambiguous(self):
        return _result([_match("cloudflare", 68, ["netblock", "cert", "headers"]),
                        _match("aws-cloudfront", 64, ["netblock", "cname", "cert"])])

    def test_close_edge_candidates_are_not_collapsed(self):
        att = attribute(self._ambiguous())
        assert att["state"] == ATT.STATE_AMBIGUOUS
        assert [c["vendor"] for c in att["candidates"]] == ["cloudflare", "aws-cloudfront"]
        # no single vendor is asserted
        assert att["vendor"] is None

    def test_each_candidate_keeps_its_own_basis_and_evidence(self):
        att = attribute(self._ambiguous())
        bases = {c["vendor"]: c["basis"] for c in att["candidates"]}
        assert bases["cloudflare"] == ["netblock", "cert", "headers"]
        assert bases["aws-cloudfront"] == ["netblock", "cname", "cert"]
        assert all(c["evidence"] for c in att["candidates"])

    def test_a_clear_winner_is_not_ambiguous(self):
        att = attribute(_result([_match("cloudflare", 82, ["netblock", "cert", "cname"]),
                                 _match("aws-cloudfront", 30, ["netblock"])]))
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "cloudflare"

    def test_two_weak_close_candidates_are_unknown(self):
        # below the floor there is nothing worth calling a tie — but a
        # near-tied pair of weak candidates is not a defensible ATTRIBUTED
        # either; the honest answer is UNKNOWN (v0.1.42 hardening)
        att = attribute(_result([_match("kong", 7, ["headers"]),
                                 _match("tyk", 7, ["headers"])]))
        assert att["state"] == ATT.STATE_UNKNOWN

    def test_two_weak_candidates_wide_gap_is_low_attribution(self):
        # one weak candidate clearly better than the other -> LOW, not UNKNOWN
        att = attribute(_result([_match("kong", 22, ["cname"]),
                                 _match("tyk", 7, ["headers"])]))
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "kong"
        assert att["confidence"] == ATT.LOW

    def test_edge_plus_origin_at_similar_scores_is_not_ambiguous(self):
        # an origin is a layer, not a competing claim about the edge
        att = attribute(_result([_match("imperva", 37, ["netblock", "headers"]),
                                 _match("nginx", 37, ["netblock", "headers"], "origin")]))
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "imperva"


class TestUnknown:
    def test_scanned_but_nothing_matched(self):
        att = attribute(_result([], headers={"server": "acme-edge"}))
        assert att["state"] == ATT.STATE_UNKNOWN
        assert att["vendor"] is None

    def test_unknown_carries_the_observations(self):
        # the scan found things; it just cannot name a vendor
        att = attribute(_result([], headers={"server": "acme-edge"},
                                cname=["edge.provider.net"]))
        labels = dict(att["observations"])
        assert labels["CNAME"] == "edge.provider.net"
        assert labels["HTTP"] == "acme-edge"
        assert labels["Issuer"] == "Example CA"


class TestInterception:
    def _intercepted(self):
        return _result([_match("cloudflare", 82, ["netblock", "cert"])],
                       interception={"by": "fortinet",
                                     "evidence": "cert issuer: Fortinet"})

    def test_state_is_intercepted(self):
        att = attribute(self._intercepted())
        assert att["state"] == ATT.STATE_INTERCEPTED

    def test_never_attributes_a_vendor_to_the_target(self):
        # completion criterion: interception is not reported as the target's
        # vendor attribution, even when a signature matched the re-signed
        # identity the middlebox presented
        att = attribute(self._intercepted())
        assert att["vendor"] is None
        assert att["score"] is None
        assert not att["evidence"]

    def test_reports_who_intercepted_and_the_observations(self):
        att = attribute(self._intercepted())
        assert att["interception"]["by"] == "fortinet"
        assert att["observations"]


class TestErrorsKeepIndependentEvidence:
    def test_error_with_dns_evidence_stays_attributed(self):
        # DNS resolves before the handshake; a connect failure does not make
        # a vendor CNAME untrue
        r = _result([_match("akamai", 20, ["cname"], "cloud")],
                    error="connect failed: timed out", no_tls=True)
        att = attribute(r)
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "akamai"
        assert att["error"] == "connect failed: timed out"

    def test_error_without_any_evidence_is_error_not_unknown(self):
        r = _result([], error="connect failed: timed out", no_tls=True)
        att = attribute(r)
        assert att["state"] == ATT.STATE_ERROR
        assert att["state"] != ATT.STATE_UNKNOWN

    def test_unknown_and_error_are_distinguishable(self):
        scanned = attribute(_result([], headers={"server": "x"}))
        failed = attribute(_result([], error="connect failed", no_tls=True))
        assert scanned["state"] == ATT.STATE_UNKNOWN
        assert failed["state"] == ATT.STATE_ERROR


class TestRoleAndObservations:
    def test_role_falls_back_to_the_signature_table(self):
        # a verdict entry without `deployment` (older --json, hand-built)
        # must still be recognised as an origin
        assert role_of({"vendor": "nginx"}) == "origin"
        assert role_of({"vendor": "cloudflare"}) == "edge"

    def test_evidence_degrades_for_older_result_trees(self):
        # no evidence_items: keep the strings rather than raising
        out = evidence_for({"evidence": ["header server: x"]})
        assert out and out[0]["details"] == ["header server: x"]

    def test_observations_are_a_view_not_a_copy(self):
        r = _result([], cname=["x.example.net"])
        assert ("CNAME", "x.example.net") in observations(r)


class TestFingerprintIntegration:
    def test_real_fingerprint_feeds_the_model(self):
        r = {"ips": ["104.18.1.79"], "cname": ["x.cdn.cloudflare.net"], "ptr": [],
             "cert": {}, "error": None,
             "tls": {"http": {"headers": {"server": "cloudflare"},
                              "set-cookie-list": []}}}
        r["verdict"] = fingerprint(r)
        att = attribute(r)
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "cloudflare"
        assert {e["category"] for e in att["evidence"]} == {"netblock", "cname", "headers"}

    def test_evidence_items_mirror_the_categories(self):
        r = {"ips": ["104.18.1.79"], "cname": [], "ptr": [], "cert": {},
             "tls": {"http": {"headers": {"server": "cloudflare"}, "set-cookie-list": []}}}
        m = fingerprint(r)[0]
        assert {i["category"] for i in m["evidence_items"]} == set(m["categories"])


class TestRendering:
    def test_default_names_edge_band_and_basis(self):
        out = fmt_compact_block(_result([
            _match("cloudflare", 82, ["netblock", "cert", "cname"], "cloud")]))
        assert "cloudflare" in out
        assert "HIGH" in out and "82" in out
        assert "net + cert + cname" in out

    def test_default_does_not_show_score_arithmetic(self):
        out = fmt_compact_block(_result([
            _match("cloudflare", 82, ["netblock", "cert", "cname"])]))
        assert "+30" not in out and "+25" not in out and "+20" not in out

    def test_verbose_explains_with_grouped_evidence(self):
        r = _result([_match("imperva", 60, ["netblock", "headers"]),
                     _match("nginx", 7, ["headers"], "origin")])
        out = fmt_block(r)
        assert "EDGE" in out
        assert "EVIDENCE" in out
        assert "Network" in out            # category label, not "netblock"
        assert "HTTP" in out
        # one category per heading, one observation per line beneath it
        lines = out.splitlines()
        net = lines.index("  Network")
        assert lines[net + 1].strip().startswith("netblock-detail")

    def test_verbose_separates_layer_from_alternatives(self):
        r = _result([_match("imperva", 60, ["netblock", "headers"]),
                     _match("nginx", 7, ["headers"], "origin")])
        out = fmt_block(r)
        assert "LAYER" in out
        assert "↓" in out                  # the stack, drawn as a stack
        assert "nginx" in out
        assert "ALTERNATIVES" not in out   # an origin is not an alternative

    def test_verbose_lists_a_competing_edge_as_an_alternative(self):
        r = _result([_match("cloudflare", 82, ["netblock", "cert", "cname"]),
                     _match("aws-cloudfront", 25, ["cert"])])
        out = fmt_block(r)
        assert "ALTERNATIVES" in out
        assert "aws-cloudfront" in out
        assert "LAYER" not in out

    def test_ambiguous_block_shows_both_candidates(self):
        out = fmt_compact_block(_result([
            _match("cloudflare", 68, ["netblock", "cert", "headers"]),
            _match("aws-cloudfront", 64, ["netblock", "cname", "cert"])]))
        assert "AMBIGUOUS" in out
        assert "cloudflare" in out and "aws-cloudfront" in out
        assert "BASIS" in out

    def test_unknown_block_shows_leads(self):
        # the triage block for an unknown edge is leads-only (the full OBSERVED
        # set is the --verbose view); the CNAME is the strongest lead and must
        # be one of them.
        out = fmt_compact_block(_result([], headers={"server": "acme-edge"},
                                        cname=["edge.provider.net"]))
        assert "UNKNOWN" in out
        assert "leads" in out
        assert "edge.provider.net" in out   # CNAME surfaced as a lead
        assert "acme-edge" in out

    def test_interception_block_warns_and_names_no_vendor(self):
        r = _result([_match("cloudflare", 82, ["cert"])],
                    interception={"by": "fortinet", "evidence": "cert issuer: Fortinet"})
        out = fmt_compact_block(r)
        assert "NOT DETERMINED" in out
        assert "INTERCEPTED" in out
        assert "interception device" in out
        assert "cloudflare" not in out     # never presented as the edge

    def test_table_reports_the_state(self):
        rows = fmt_summary_table([
            _result([_match("cloudflare", 68, ["netblock", "cert", "headers"]),
                     _match("aws-cloudfront", 64, ["netblock", "cname", "cert"])]),
        ])
        assert "AMBIGUOUS" in rows

    def test_table_marks_interception_instead_of_the_vendor(self):
        r = _result([_match("cloudflare", 82, ["cert"])],
                    interception={"by": "fortinet", "evidence": "x"})
        rows = fmt_summary_table([r])
        assert "INTERCEPTED" in rows
        assert "cloudflare" not in rows

    def test_errored_host_with_evidence_shows_both(self):
        r = _result([_match("akamai", 20, ["cname"], "cloud")],
                    error="connect failed: timed out", no_tls=True)
        out = fmt_compact_block(r)
        assert "akamai" in out
        assert "connect failed" in out


class TestMachineOutputs:
    """Machine surfaces must carry the state and must not mis-file an
    intercepted host under the target's vendor."""

    def test_csv_appends_state_without_moving_columns(self):
        import csv
        import io

        from w4f.report import CSV_HEADER, csv_doc
        assert CSV_HEADER[-1] == "state"
        # every pre-0.1.35 column keeps its index
        assert CSV_HEADER[:16] == [
            "host", "port", "ips", "cname", "verdict", "confidence", "signals",
            "mtls", "tls_version", "alpn", "spki", "http_status", "block",
            "error", "basis", "final_host"]
        rows = list(csv.reader(io.StringIO(csv_doc([
            _result([_match("cloudflare", 82, ["netblock", "cert"])])]))))
        assert rows[1][-1] == ATT.STATE_ATTRIBUTED

    def test_sarif_files_interception_under_its_own_rule(self):
        import json

        from w4f.report import sarif_doc
        r = _result([_match("cloudflare", 82, ["cert"])],
                    interception={"by": "fortinet", "evidence": "cert issuer: Fortinet"})
        doc = json.loads(sarif_doc([r]))
        res = doc["runs"][0]["results"][0]
        assert res["ruleId"] == "w4f/interception"
        assert "cloudflare" not in res["message"]["text"]
        assert res["properties"]["state"] == ATT.STATE_INTERCEPTED

    def test_sarif_carries_state_and_band(self):
        import json

        from w4f.report import sarif_doc
        doc = json.loads(sarif_doc([
            _result([_match("cloudflare", 82, ["netblock", "cert"])])]))
        props = doc["runs"][0]["results"][0]["properties"]
        assert props["state"] == ATT.STATE_ATTRIBUTED
        assert props["confidence_band"] == ATT.HIGH


def test_no_trailing_whitespace_in_blocks():
    """Every rendered line is clean — trailing spaces show up in diffs and
    in copied output."""
    cases = [
        _result([_match("cloudflare", 82, ["netblock", "cert"])]),
        _result([], headers={"server": "acme"}),
        _result([_match("cloudflare", 68, ["netblock", "cert", "headers"]),
                 _match("aws-cloudfront", 64, ["netblock", "cname", "cert"])]),
        _result([_match("cloudflare", 82, ["cert"])],
                interception={"by": "fortinet", "evidence": "x"}),
        _result([], error="connect failed", no_tls=True),
    ]
    for r in cases:
        for line in fmt_compact_block(r).splitlines():
            assert line == line.rstrip(), f"trailing whitespace: {line!r}"
        for line in fmt_block(r).splitlines():
            assert line == line.rstrip(), f"trailing whitespace (verbose): {line!r}"


class TestEvidenceConflicts:
    """Strong evidence must never be overridden by weak generic evidence
    (v0.1.42 hardening; the v0.1.41 financial validation collision cases)."""

    def test_strong_network_beats_weak_header(self):
        # vendor A netblock (30) vs vendor B header (7): A wins decisively
        att = attribute(_result([_match("cloudflare", 30, ["netblock"]),
                                 _match("myra", 7, ["headers"])]))
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "cloudflare"
        assert att["confidence"] == ATT.MEDIUM

    def test_strong_cname_beats_generic_origin_server(self):
        # A cname (20) vs a generic origin server: the origin is a LAYER
        att = attribute(_result([_match("akamai", 20, ["cname"]),
                                 _match("apache", 7, ["headers"], "origin")]))
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "akamai"
        assert [l["vendor"] for l in att["layers"]] == ["apache"]

    def test_certificate_beats_generic_http_marker(self):
        att = attribute(_result([_match("cloudflare", 20, ["cert"]),
                                 _match("openresty", 7, ["headers"], "origin")]))
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "cloudflare"

    def test_strong_edge_plus_unrelated_origin_tech_is_one_winner(self):
        # edge + origin tech at SIMILAR scores: the origin is a layer, not
        # a rival — never AMBIGUOUS and never a surprise primary
        att = attribute(_result([_match("imperva", 37, ["netblock", "headers"]),
                                 _match("varnish", 30, ["netblock", "headers"], "origin")]))
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "imperva"
        assert [l["vendor"] for l in att["layers"]] == ["varnish"]

    def test_strong_a_plus_weak_b_header_keeps_b_as_alternative(self):
        att = attribute(_result([_match("akamai", 47, ["netblock", "cname", "headers"]),
                                 _match("wordpress-vip", 7, ["headers"])]))
        assert att["state"] == ATT.STATE_ATTRIBUTED
        assert att["vendor"] == "akamai"
        alts = {a["vendor"] for a in att["alternatives"]}
        assert "wordpress-vip" in alts

    def test_two_genuinely_strong_edges_are_ambiguous(self):
        att = attribute(_result([_match("cloudflare", 37, ["netblock", "headers"]),
                                 _match("aws-cloudfront", 40, ["cname", "cert"])]))
        assert att["state"] == ATT.STATE_AMBIGUOUS
        assert att["vendor"] is None

    def test_network_ptr_vs_http_header_close_call_is_unknown(self):
        # the v0.1.41 allianz/miraeasset pattern: a network-level PTR (15)
        # vs an HTTP header (7) — both weak, gap within the margin,
        # neither defensible as the edge -> UNKNOWN, not a coin flip
        att = attribute(_result([_match("aws-global-accelerator", 15, ["ptr"]),
                                 _match("cloudflare", 7, ["headers"])]))
        assert att["state"] == ATT.STATE_UNKNOWN
        assert att["vendor"] is None
