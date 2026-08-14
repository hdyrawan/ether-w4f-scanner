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
        "verdict": [{"vendor": "cloudflare", "signals": 3,
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
        # pytest capture is not a TTY — verdict line must be plain
        from w4f.report import _verdict_line
        line = _verdict_line([{"vendor": "cloudflare", "signals": 3,
                               "confidence": 82, "evidence": []}])
        assert "\033[" not in line
        assert "cloudflare (3, 82%)" in line


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
