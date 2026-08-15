"""Report and banner tests: console output stays plain, markdown stays md."""

from __future__ import annotations

from w4f.banner import BANNER, render_banner
from w4f.report import fmt_block, md_doc


def _result_with_verdict():
    return {
        "host": "api.example.com",
        "hostport": "api.example.com:443",
        "port": 443,
        "resolved": {"ips": ["104.18.1.79"], "cname": ["api.example.com.cdn.cloudflare.net"],
                     "ptr": []},
        "cname": ["api.example.com.cdn.cloudflare.net"],
        "ptr": [],
        "ips": ["104.18.1.79"],
        "tls": {
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "alpn": "h2",
            "mtls": False,
            "http": {"status": "HTTP/1.1 200 OK",
                     "headers": {"server": "cloudflare", "cf-ray": "abc"},
                     "set-cookie-list": []},
            "cert": {"subject": "CN=api.example.com", "issuer": "O=Example CA",
                     "issuer_org": "Example CA", "san": "api.example.com",
                     "not_before": "2026-01-01T00:00:00", "not_after": "2027-01-01T00:00:00",
                     "days_remaining": 100, "spki_sha256": "a" * 64,
                     "key_type": "RSA", "key_size": 2048,
                     "signature": "sha256WithRSAEncryption"},
        },
        "cert": {"issuer_org": "Example CA", "spki_sha256": "a" * 64},
        "mtls": False,
        "chain_verified": True,
        "verdict": [{"vendor": "cloudflare", "signals": 3, "confidence": 82,
                     # netblock 30 + cert 25 + cname 20 + headers 7 = 82
                     "categories": ["netblock", "cert", "cname", "headers"],
                     "evidence": ["header server: cloudflare", "header cf-ray: abc",
                                  "cname: api.example.com.cdn.cloudflare.net"]}],
    }


class TestFmtBlock:
    def test_no_markdown_in_console_output(self):
        block = fmt_block(_result_with_verdict())
        assert "**" not in block
        assert not block.lstrip().startswith("- **")
        assert not block.lstrip().startswith("###")

    def test_has_labels_and_values(self):
        block = fmt_block(_result_with_verdict())
        assert "api.example.com:443" in block
        assert "cloudflare" in block
        assert "cf-ray" in block

    def test_error_block(self):
        block = fmt_block({"hostport": "x.com:443", "error": "DNS did not resolve"})
        assert "x.com:443" in block
        assert "DNS did not resolve" in block

    def test_block_probe_line(self):
        r = _result_with_verdict()
        r["block"] = {"vendor": "fortiweb", "title": "the url you requested has been blocked",
                      "status": "HTTP/1.1 500"}
        block = fmt_block(r)
        assert "fortiweb" in block


class TestVendorColors:
    def test_distinct_colors_per_vendor(self):
        # a glance must name the edge: the big vendors get distinct hues,
        # plain origins are dim, family prefixes (aws-*) share a hue
        from w4f.report import _vendor_color
        import sys as _sys
        from unittest import mock
        class T:
            def isatty(self): return True
            def write(self, s): pass
        with mock.patch.object(_sys, "stdout", T()):
            colors = {v: _vendor_color(v) for v in
                      ["cloudflare", "akamai", "fastly", "nginx", "aws-waf",
                       "aws-cloudfront", "kong"]}
        assert colors["cloudflare"] != colors["akamai"]
        assert colors["cloudflare"] != colors["fastly"]
        assert colors["nginx"] == "\033[2m"          # origin = dim
        assert colors["aws-waf"] == colors["aws-cloudfront"]  # family prefix

    def test_no_color_env_disables(self, monkeypatch):
        from w4f.report import _vendor_color
        monkeypatch.setenv("NO_COLOR", "1")
        assert _vendor_color("cloudflare") == ""

    def test_non_tty_is_plain(self):
        # pytest capture is not a TTY — the block must carry no escapes
        from w4f.report import fmt_compact_block
        out = fmt_compact_block(_result_with_verdict())
        assert "\033[" not in out
        assert "cloudflare" in out

    def test_primary_then_alternatives(self):
        # the primary attribution leads; layers underneath follow it
        from w4f.report import fmt_compact_block
        r = _result_with_verdict()
        r["verdict"] = [
            {"vendor": "imperva", "signals": 2, "confidence": 60,
             "categories": ["netblock", "headers"], "evidence": ["x-iinfo"]},
            {"vendor": "nginx", "signals": 1, "confidence": 7,
             "categories": ["headers"], "deployment": "origin",
             "evidence": ["header server: nginx"]},
        ]
        lines = [ln for ln in fmt_compact_block(r).splitlines() if ln.strip()]
        assert "imperva" in lines[1]
        assert any("nginx" in ln and "layer" in ln for ln in lines)


def _results_fixture():
    r1 = _result_with_verdict()
    r2 = _result_with_verdict()
    r2["host"] = r2["hostport"] = "bank.example.net:443"
    r2["verdict"] = [{"vendor": "imperva", "signals": 2, "confidence": 60,
                      "categories": ["netblock", "headers"],
                      "evidence": ["header x-iinfo: 1-2-3", "netblock: 1.2.3.4 in 1.2.3.0/24"]},
                     {"vendor": "nginx", "signals": 1, "confidence": 7,
                      "categories": ["headers"], "evidence": ["header server: nginx"]}]
    r2["tls"]["mtls"] = True
    r3 = {"host": "dead.example.io", "hostport": "dead.example.io:443",
          "error": "DNS did not resolve", "tls": {}, "verdict": []}
    return [r1, r2, r3]


class TestSummaryTable:
    def _results(self):
        return _results_fixture()

    def test_header_and_rows(self):
        from w4f.report import fmt_summary_table
        out = fmt_summary_table(self._results())
        assert "HOST" in out and "EDGE" in out and "CONF" in out
        # detail columns added in 0.1.32
        assert "BASIS" in out and "TLS" in out and "CERT" in out
        assert "HTTP" in out and "NOTES" in out
        assert "cloudflare" in out and "imperva" in out
        assert "DNS did not resolve" in out

    def test_errored_host_has_no_edge_and_unscanned_has_unknown(self):
        # a host that failed to probe reports "-": "unknown" would claim we
        # looked and found nothing. A host that WAS scanned reports "unknown".
        from w4f.report import fmt_summary_table
        rs = _results_fixture()
        rs[0]["verdict"] = []                       # scanned, nothing matched
        rows = fmt_summary_table(rs).splitlines()
        scanned = next(ln for ln in rows if ln.startswith("api.example.com"))
        failed = next(ln for ln in rows if ln.startswith("dead.example.io"))
        assert "unknown" in scanned
        assert "unknown" not in failed
        assert "ERR DNS did not resolve" in failed

    def test_critical_flags_present(self):
        from w4f.report import fmt_summary_table
        out = fmt_summary_table(self._results())
        assert "mTLS" in out                 # flag token for the imperva host
        assert "ERR DNS did not resolve" in out  # reason travels with the flag

    def test_basis_column_names_signal_categories(self):
        from w4f.report import fmt_summary_table
        out = fmt_summary_table(self._results())
        assert "net+cert+cname+http" in out  # cloudflare host
        assert "net+http" in out             # imperva host

    def test_secondary_vendor_count_marked(self):
        from w4f.report import fmt_summary_table
        out = fmt_summary_table(self._results())
        assert "imperva +1" in out           # nginx underneath

    def test_columns_align_when_colored(self, monkeypatch):
        # padding must use the PLAIN cell length — padding inside the ANSI
        # escape shifts every column to the right. The exact property: the
        # colored render with escapes stripped IS the plain render.
        import re as _re
        import sys as _sys
        from unittest import mock
        from w4f.report import fmt_summary_table

        plain = fmt_summary_table(self._results())   # pytest capture: no TTY

        class T:
            def isatty(self): return True
            def write(self, s): pass
        monkeypatch.setenv("COLUMNS", "200")
        with mock.patch.object(_sys, "stdout", T()):
            colored = fmt_summary_table(self._results())
        assert "\033[" in colored                    # actually colored
        assert _re.sub(r"\033\[[0-9;]*m", "", colored) == plain

    def test_conf_cell_is_band_first(self):
        from w4f.report import fmt_summary_table
        out = fmt_summary_table(self._results())
        assert "HIGH 82" in out          # band, then score
        assert "MED 60" in out

    def test_no_markdown(self):
        from w4f.report import fmt_summary_table
        out = fmt_summary_table(self._results())
        assert "**" not in out
        assert not out.lstrip().startswith("|")

    def test_plain_when_not_tty(self):
        from w4f.report import fmt_summary_table
        assert "\033[" not in fmt_summary_table(self._results())

    def test_empty(self):
        from w4f.report import fmt_summary_table
        assert fmt_summary_table([]) == ""


class TestCompactBlock:
    def test_host_and_verdict(self):
        from w4f.report import fmt_compact_block
        out = fmt_compact_block(_result_with_verdict())
        assert "api.example.com:443" in out
        assert "cloudflare" in out
        assert "HIGH" in out and "82" in out          # band first, score after
        assert "net + cert + cname + http" in out     # basis, spaced

    def test_block_adds_facts_the_table_lacks(self):
        # the block carries what the table row cannot: path, cert, pin.
        # Raw evidence strings moved to --verbose (the analytical view).
        from w4f.report import fmt_compact_block
        out = fmt_compact_block(_result_with_verdict())
        assert "200" in out                            # path
        assert "1.3 h2" in out                         # TLS row
        assert "Example CA" in out and "100d left" in out
        assert "chain verified" in out
        assert "SPKI" in out and "aaaa" in out         # pin (truncated)

    def test_san_shown_in_triage_view(self):
        # the cert's scope (sibling hosts, wildcard reach) is triage material,
        # not verbose-only detail
        from w4f.report import fmt_compact_block
        r = _result_with_verdict()
        r["tls"]["cert"]["san"] = "api.example.com, www.api.example.com"
        out = fmt_compact_block(r)
        assert "san" in out
        assert "api.example.com, www.api.example.com" in out

    def test_san_capped_tighter_than_verbose(self):
        from w4f.report import fmt_block, fmt_compact_block
        r = _result_with_verdict()
        r["tls"]["cert"]["san"] = ", ".join(f"h{i}.example.com" for i in range(9))
        compact = fmt_compact_block(r)
        assert "h0.example.com, h1.example.com, h2.example.com" in compact
        assert "(+6 more)" in compact       # 3 shown in the triage block
        assert "h3.example.com" not in compact
        assert "(+3 more)" in fmt_block(r)  # 6 shown under --verbose

    def test_no_san_row_when_cert_has_none(self):
        from w4f.report import fmt_compact_block
        r = _result_with_verdict()
        r["tls"]["cert"].pop("san", None)
        assert "\n  san" not in fmt_compact_block(r)

    def test_layer_is_shown_separately_from_alternatives(self):
        # an origin under the edge is a LAYER of the stack, never presented
        # as a competing edge vendor
        from w4f.report import fmt_compact_block
        out = fmt_compact_block(_results_fixture()[1])
        assert "imperva" in out
        assert "layer" in out and "nginx" in out
        assert "alternative" not in out.lower()

    def test_weak_verdict_marked(self):
        from w4f.report import fmt_compact_block
        r = _result_with_verdict()
        r["verdict"] = [{"vendor": "nginx", "signals": 1, "confidence": 7,
                         "categories": ["headers"], "evidence": ["header server: nginx"]}]
        assert "spoofable" in fmt_compact_block(r)

    def test_unknown_edge_shows_signature_leads(self):
        # an unknown verdict is a tool gap — print the headers that matched
        # nothing so the sweep feeds the next signature file
        from w4f.report import fmt_compact_block
        r = _result_with_verdict()
        r["verdict"] = []
        r["tls"]["http"]["headers"] = {
            "server": "acme-edge", "x-acme-pop": "sin1",
            "content-type": "text/html", "x-frame-options": "deny",
        }
        out = fmt_compact_block(r)
        assert "UNKNOWN" in out
        assert "server: acme-edge" in out
        assert "x-acme-pop: sin1" in out
        assert "content-type" not in out      # noise excluded
        assert "x-frame-options" not in out   # generic security header excluded

    def test_redirect_chain_shown(self):
        from w4f.report import fmt_compact_block
        r = _result_with_verdict()
        r["tls"]["http"]["redirects"] = ["https://www.api.example.com/"]
        r["tls"]["http"]["final_host"] = "www.api.example.com"
        out = fmt_compact_block(r)
        assert "www.api.example.com" in out
        assert "1 hop" in out

    def test_critical_flags(self):
        from w4f.report import fmt_compact_block
        r = _result_with_verdict()
        r["tls"]["mtls"] = True
        r["block"] = {"vendor": "fortiweb", "title": "blocked", "status": "500"}
        out = fmt_compact_block(r)
        assert "mTLS" in out
        assert "BLOCK fortiweb" in out

    def test_error_host(self):
        from w4f.report import fmt_compact_block
        out = fmt_compact_block({"hostport": "x.com:443", "error": "DNS did not resolve"})
        assert "ERR" in out
        assert "DNS did not resolve" in out

    def test_no_markdown(self):
        from w4f.report import fmt_compact_block
        assert "**" not in fmt_compact_block(_result_with_verdict())


class TestMdDoc:
    def test_markdown_preserved(self):
        doc = md_doc([_result_with_verdict()])
        assert doc.startswith("# Endpoint fingerprint sweep")
        assert "| Endpoint |" in doc
        assert "### api.example.com:443" in doc
        assert "**Verdict**" in doc

    def test_empty_results(self):
        doc = md_doc([])
        assert doc.startswith("# Endpoint fingerprint sweep")


class TestBanner:
    def test_banner_renders(self):
        assert BANNER
        assert "w4f" in BANNER or "██" in BANNER  # the art glyphs

    def test_colors_present(self):
        assert "\033[31m" in BANNER  # red for 'w'
        assert "\033[34m" in BANNER  # blue for 'f'

    def test_no_trailing_blank_rows(self):
        # Regression: ANSI codes hid blank rows from the trim
        lines = BANNER.split("\n")
        assert lines[-1].strip("\x1b[0m ").strip() != ""

    def test_custom_colors(self):
        out = render_banner("w4f", {"w": "\033[32m", "f": "\033[35m"})
        assert "\033[32m" in out and "\033[35m" in out


class TestRollup:
    def test_counts_edges_and_flags(self):
        from w4f.report import fmt_rollup
        out = fmt_rollup(_results_fixture(), elapsed=12.5)
        assert "3 hosts" in out
        assert "12.5s" in out
        assert "cloudflare 1" in out and "imperva 1" in out
        assert "mTLS 1" in out
        assert "errors 1" in out

    def test_unknown_hosts_named(self):
        # the unknown list is the signature-mining queue — name the hosts
        from w4f.report import fmt_rollup
        rs = _results_fixture()
        rs[0]["verdict"] = []
        out = fmt_rollup(rs)
        assert "unknown" in out
        assert "api.example.com:443" in out

    def test_weak_verdicts_called_out(self):
        from w4f.report import fmt_rollup
        rs = _results_fixture()
        rs[0]["verdict"] = [{"vendor": "nginx", "signals": 1, "confidence": 7,
                             "categories": ["headers"], "evidence": []}]
        out = fmt_rollup(rs)
        assert "headers only" in out

    def test_empty(self):
        from w4f.report import fmt_rollup
        assert fmt_rollup([]) == ""

    def test_plain_when_not_tty(self):
        from w4f.report import fmt_rollup
        assert "\033[" not in fmt_rollup(_results_fixture(), elapsed=1.0)


class TestDisplayOrder:
    def test_risk_first_puts_problems_on_top(self):
        from w4f.cli import display_order
        rs = _results_fixture()          # cloudflare(ok), imperva(mTLS), error
        order = [r["hostport"] for r in display_order(rs, "risk")]
        assert order[0] == "dead.example.io:443"     # error
        assert order[1] == "bank.example.net:443"    # mTLS
        assert order[2] == "api.example.com:443"     # clean, identified

    def test_host_mode_is_alphabetical(self):
        from w4f.cli import display_order
        order = [r["hostport"] for r in display_order(_results_fixture(), "host")]
        assert order == sorted(order)

    def test_edge_mode_groups_by_vendor(self):
        from w4f.cli import display_order
        order = [(r.get("verdict") or [{}])[0].get("vendor", "~unknown")
                 for r in display_order(_results_fixture(), "edge")]
        assert order == sorted(order)

    def test_file_outputs_stay_host_sorted(self):
        # display ordering must not mutate the list the file writers use
        from w4f.cli import display_order
        rs = _results_fixture()
        before = [r["hostport"] for r in rs]
        display_order(rs, "risk")
        assert [r["hostport"] for r in rs] == before


class TestErroredHostStillShowsEvidence:
    """A connect failure can still carry DNS-level evidence (CNAME/PTR/
    netblock resolve before the handshake) — the report must not hide it."""

    def _errored_with_dns_verdict(self):
        return {
            "host": "x.example.com", "hostport": "x.example.com:443",
            "error": "connect failed: timed out",
            "cname": ["x.example.com.edgekey.net"], "ips": [], "ptr": [],
            "tls": {"tls_error": "connect failed: timed out"},
            "verdict": [{"vendor": "akamai", "signals": 1, "confidence": 20,
                         "categories": ["cname"],
                         "evidence": ["cname: x.example.com.edgekey.net"]}],
        }

    def test_table_keeps_the_dns_verdict(self):
        from w4f.report import fmt_summary_table
        out = fmt_summary_table([self._errored_with_dns_verdict()])
        assert "akamai" in out            # not replaced by "-"
        assert "connect failed" in out    # error still flagged

    def test_table_shows_dash_when_nothing_was_learned(self):
        from w4f.report import fmt_summary_table
        r = self._errored_with_dns_verdict()
        r["verdict"] = []
        out = fmt_summary_table([r])
        assert "unknown" not in out       # never scanned != unknown edge
        assert "ERR connect failed" in out

    def test_block_renders_error_and_evidence(self):
        from w4f.report import fmt_compact_block
        out = fmt_compact_block(self._errored_with_dns_verdict())
        assert "connect failed" in out
        assert "akamai" in out
        assert "cname" in out

    def test_block_stops_after_error_when_nothing_collected(self):
        from w4f.report import fmt_compact_block
        r = self._errored_with_dns_verdict()
        r["verdict"] = []
        out = fmt_compact_block(r)
        assert "connect failed" in out
        assert "unknown — no signature matched" not in out
