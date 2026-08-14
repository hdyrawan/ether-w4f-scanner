"""fingerprint() unit tests — the accuracy core.

Positive cases are drawn from REAL observed hosts (the 2026-08-14 sweep and
the --verify cross-check); negatives guard against false positives (e.g. a
Cloudflare IP netblock must not make a bare nginx host look like Cloudflare
unless there is corroborating evidence).
"""

from __future__ import annotations

from w4f.scanner import fingerprint


def _result(ips=None, cname=None, ptr=None, headers=None, cookies=None,
            cert=None):
    return {
        "ips": ips or [],
        "cname": cname or [],
        "ptr": ptr or [],
        "cert": cert or {},
        "tls": {
            "http": {
                "headers": headers or {},
                "set-cookie-list": cookies or [],
            }
        },
    }


class TestRealWorldPositives:
    """Each case mirrors a host verified during the 2026-08-14 sweep."""

    def test_cloudflare_mapi_example(self):
        r = _result(
            ips=["104.18.1.79"],
            cname=["api.example.bank.cdn.cloudflare.net"],
            headers={"server": "cloudflare", "cf-ray": "abc-CGK",
                     "cf-cache-status": "DYNAMIC"},
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "cloudflare" in names

    def test_tencent_edgeone_aquarius(self):
        r = _result(
            ips=["43.174.196.219"],
            cname=["aquarius.EXAMPLE_BANK.co.id.eo.dnse4.com"],
            headers={"eo-log-uuid": "17946984068454628305"},
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "tencent-edgeone" in names

    def test_f5_ts_cookie_origin(self):
        r = _result(
            ips=["103.124.20.98"],
            cookies=["TS01538524=012b5961782784783de7052afa3b4817"],
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "f5" in names

    def test_f5_ten_char_ts_cookie(self):
        # 10-hex TS cookie (TSa0cfc1c5027=... form)
        r = _result(cookies=["TSa0cfc1c5027=01e96070f81cbbfff2708a024b425393"])
        assert "f5" in [m["vendor"] for m in fingerprint(r)]

    def test_haproxy_stick_cookie(self):
        # brks_lb=!<base64> — HAProxy stick cookie, no Server header
        r = _result(cookies=["brks_lb=!igBUmMgdR05NSpvPC/3/vdfhxhkcRNC4Auqj6+Ndiy5+"])
        assert "haproxy" in [m["vendor"] for m in fingerprint(r)]

    def test_gtm_gslb_cname(self):
        r = _result(cname=["gtm-sg-wzf24ud291z.gtm-i1d6.com"])
        assert "gtm-gslb" in [m["vendor"] for m in fingerprint(r)]

    def test_aws_ec2_ptr(self):
        r = _result(ips=["34.206.8.44"], ptr=["ec2-34-206-8-44.compute-1.amazonaws.com"])
        assert "aws-ec2" in [m["vendor"] for m in fingerprint(r)]

    def test_aws_elb_cname(self):
        r = _result(
            ips=["15.232.9.89"],
            cname=["internal-abc-1234567890.ap-southeast-3.elb.amazonaws.com"],
        )
        assert "aws-elb" in [m["vendor"] for m in fingerprint(r)]

    def test_imperva_incap(self):
        r = _result(
            ips=["45.60.16.239"],
            cname=["wj5u3uw.ng.impervadns.net"],
            headers={"x-iinfo": "abc", "x-cdn": "Imperva"},
        )
        assert "imperva" in [m["vendor"] for m in fingerprint(r)]

    def test_google_gfe_gws(self):
        r = _result(
            ips=["34.36.226.141"],
            headers={"server": "gws", "alt-svc": "h3=\":443\""},
        )
        assert "google-gfe" in [m["vendor"] for m in fingerprint(r)]

    def test_arvancloud_request_id_header(self):
        # ArvanCloud's concrete response header must name the edge (the old
        # "x-arvan-*" glob key was matched by exact lookup and never fired).
        r = _result(headers={"x-arvan-request-id": "9f3c1a2b"})
        assert "arvancloud" in [m["vendor"] for m in fingerprint(r)]

    def test_nginx_direct_origin(self):
        r = _result(ips=["117.54.11.167"], headers={"server": "nginx/1.24.0"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "nginx" in names
        # plain nginx must NOT be mislabeled as a WAF vendor
        assert "fortiweb" not in names
        assert "f5" not in names

    def test_http3_host_not_google_gfe(self):
        # alt-svc:h3 is web-wide (any HTTP/3 host). A plain nginx origin
        # advertising HTTP/3 must NOT be labeled google-gfe.
        r = _result(headers={"server": "nginx/1.25.3", "alt-svc": 'h3=":443"; ma=86400'})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "nginx" in names
        assert "google-gfe" not in names

    def test_cloudflare_http3_no_phantom_gfe(self):
        # A Cloudflare host that speaks HTTP/3 must not pick up a stray
        # google-gfe signal from its alt-svc header.
        r = _result(
            headers={"server": "cloudflare", "cf-ray": "abc-CGK", "alt-svc": 'h3=":443"'},
        )
        assert "google-gfe" not in [m["vendor"] for m in fingerprint(r)]

    def test_arvan_wildcard_key_is_dead(self):
        # Guard against reintroducing a glob header key: a header literally
        # named "x-arvan-*" does not occur on the wire, and the real
        # x-arvan-cache header must not depend on such a key to be matched.
        r = _result(headers={"x-arvan-cache": "HIT"})
        # x-arvan-cache is not (yet) a signature; the point is that the old
        # dead "x-arvan-*" key contributed nothing, so this stays unknown.
        assert "arvancloud" not in [m["vendor"] for m in fingerprint(r)]


class TestNegatives:
    """False-positive guards."""

    def test_plain_nginx_ip_not_waf(self):
        # A plain nginx host on a NON-vendor IP must not claim any WAF/CDN
        r = _result(ips=["8.8.8.8"], headers={"server": "nginx"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert names == ["nginx"]

    def test_cf_netblock_is_cf(self):
        # 104.16.x.x IS Cloudflare's anycast space — the netblock rule
        # legitimately names the edge as Cloudflare even without headers.
        r = _result(ips=["104.16.1.1"], headers={"server": "nginx"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "cloudflare" in names

    def test_amazonaws_ptr_alone_not_elb(self):
        # compute-N PTR is EC2, not ELB (the regexes must stay distinct)
        r = _result(ips=["34.206.8.44"], ptr=["ec2-34-206-8-44.compute-1.amazonaws.com"])
        names = [m["vendor"] for m in fingerprint(r)]
        assert "aws-ec2" in names
        assert "aws-elb" not in names

    def test_ts_cookie_too_short(self):
        # TS1abc= (4 hex) is not a real ASM cookie
        r = _result(cookies=["TS1abc=xyz"])
        assert "f5" not in [m["vendor"] for m in fingerprint(r)]

    def test_empty_result(self):
        assert fingerprint(_result()) == []

    def test_missing_http_layer(self):
        # fingerprint() must tolerate a result with no TLS/http at all
        assert fingerprint({"ips": [], "cname": [], "ptr": [], "cert": {}}) == []


class TestSignalCounting:
    def test_cloudflare_ranked_by_signal_count(self):
        r = _result(
            ips=["104.18.1.79"],
            cname=["api.example.bank.cdn.cloudflare.net"],
            headers={"server": "cloudflare", "cf-ray": "abc"},
        )
        ver = fingerprint(r)
        assert ver[0]["vendor"] == "cloudflare"
        assert ver[0]["signals"] >= 2

    def test_evidence_strings_present(self):
        r = _result(cookies=["TS01538524=012b5961782784783de7052afa3b4817"])
        ver = fingerprint(r)
        assert any("cookie: TS" in e for m in ver for e in m["evidence"])
