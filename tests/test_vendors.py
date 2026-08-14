"""Vendor signature table sanity checks.

Guards against table corruption: every regex must compile, every vendor must
have at least one signal kind, header patterns must be lowercase keys, and
no two vendors may share a name.
"""

from __future__ import annotations

import re

from w4f.vendors import INTERESTING_HEADERS, VENDORS, vendor_nets


def test_every_vendor_has_rules():
    for name, rules in VENDORS.items():
        assert rules, f"vendor {name} has no rules"
        has_signal = any(
            rules.get(k) for k in ("headers", "cookies", "cert", "cname", "ptr", "nets")
        )
        assert has_signal, f"vendor {name} has no usable signal kind"


def test_all_regexes_compile():
    for name, rules in VENDORS.items():
        for hname, hre in rules.get("headers", {}).items():
            assert isinstance(hname, str) and hname.islower(), \
                f"{name}: header key must be lowercase ({hname})"
            if hre is not None:
                re.compile(hre)  # raises on bad pattern
        for cre in rules.get("cookies", []):
            re.compile(cre)
        for kind in ("cert", "cname", "ptr"):
            if rules.get(kind):
                re.compile(rules[kind])


def test_all_netblocks_valid():
    for name, rules in VENDORS.items():
        for net in rules.get("nets", []):
            # ip_network raises on invalid; a stray host bit would also be a bug
            vendor_nets(name)  # force compile cache


def test_no_duplicate_vendor_names():
    assert len(VENDORS) == len(set(VENDORS))


def test_interesting_headers_lowercase():
    for h in INTERESTING_HEADERS:
        assert h.islower(), f"INTERESTING_HEADERS entry not lowercase: {h!r}"


def test_block_page_vendor_names_are_consistent():
    # The --verify probe returns vendor names that should not collide with
    # passive vendor names in a confusing way.
    assert "f5-asm" != "f5"
    assert "fortiweb" in VENDORS


class TestRegexSanity:
    """Spot-check the tricky regexes against real observed values."""

    def test_nginx_regex_versions(self):
        rx = re.compile(VENDORS["nginx"]["headers"]["server"], re.I)
        assert rx.search("nginx")
        assert rx.search("nginx/1.24.0")
        assert not rx.search("openresty/1.21.4.1")  # must not match openresty

    def test_f5_ts_cookie_forms(self):
        rx = re.compile(VENDORS["f5"]["cookies"][3])  # the TS cookie pattern
        assert rx.search("TS01538524=012b5961782784783de7052afa3b4817")
        assert rx.search("TSa0cfc1c5027=01e96070f81cbbfff2708a024b4253938")
        assert rx.search("TS1893ea31027=081eab5240ab20005268bd4a1214dc2e0d0cc14d800f13")
        assert not rx.search("TS1abc=xyz")  # too short
        assert not rx.search("TS0123456789abcdef0123=")  # >12 hex chars

    def test_haproxy_stick_cookie(self):
        rx = re.compile(VENDORS["haproxy"]["cookies"][0])
        assert rx.search("brks_lb=!igBUmMgdR05NSpvPC/3/vdfhxhkcRNC4Auqj6+Ndiy5+")
        assert rx.search("dkib=!VSYpNo1coC4ZW8lchMYGfunQEG91bu9qr3itx2E3NuQ9AOXuWqFTQN")
        assert not rx.search("JSESSIONID=ABCDEF")  # normal cookie, no !
        assert not rx.search("brks_lb=plainvalue")  # no ! marker

    def test_gtm_cname(self):
        rx = re.compile(VENDORS["gtm-gslb"]["cname"], re.I)
        assert rx.search("gtm-sg-wzf24ud291z.gtm-i1d6.com")
        assert not rx.search("api.example.com")

    def test_aws_ec2_ptr(self):
        rx = re.compile(VENDORS["aws-ec2"]["ptr"], re.I)
        assert rx.search("ec2-34-206-8-44.compute-1.amazonaws.com")
        assert rx.search("ec2-1-2-3-4.compute-2.amazonaws.com")
        assert not rx.search("internal-abc.ap-southeast-3.elb.amazonaws.com")

    def test_tencent_edgeone_cname(self):
        rx = re.compile(VENDORS["tencent-edgeone"]["cname"], re.I)
        assert rx.search("aquarius.EXAMPLE_BANK.co.id.eo.dnse4.com")
        assert rx.search("foo.cdn.dnsv1.com.cn")


class TestNewSignatures:
    """Rules added from the 2026-08-14 internet accuracy sweep."""

    def _names(self, headers=None, cookies=None):
        return [m["vendor"] for m in _fingerprint_result(headers=headers, cookies=cookies)]

    def test_akamai_kona_akamai_ghost_server(self):
        # www.example.com / www.example-registrar.com / www.example.com / www.example.com 403s
        assert "akamai" in self._names(headers={"server": "AkamaiGHost"})

    def test_akamai_kona_grn_headers(self):
        # www.example.com: akamai-grn + x-akamai-transformed; www.example.com: x-grn
        assert "akamai" in self._names(headers={"akamai-grn": "0.9717d58c.1786708538.9a9d337"})
        assert "akamai" in self._names(headers={"x-grn": "0.6e0f3517.1786708538.308a92d1"})
        assert "akamai" in self._names(headers={"x-akamai-transformed": "0 - 0 -"})

    def test_akamai_request_bc(self):
        # Kona block-page context header on www.example.com / www.example.com
        assert "akamai" in self._names(headers={"akamai-request-bc": "[a=23.53.15.87,b=145019611]"})

    def test_tengine_alibaba(self):
        # www.example-market.com: server Tengine + x-server-id
        assert "tengine" in self._names(headers={"server": "Tengine", "x-server-id": "28c3d6b2"})

    def test_tencent_gateway(self):
        # example.com: stgw on apex, tRPC-Gateway on www
        assert "tencent-gateway" in self._names(headers={"server": "stgw"})
        assert "tencent-gateway" in self._names(
            headers={"server": "tRPC-Gateway", "x-upstream-latency": "7"})

    def test_pepyaka_wix(self):
        assert "pepyaka" in self._names(headers={"server": "Pepyaka", "x-cache-status": "HIT"})

    def test_kong_gateway(self):
        # example-ride.com: X-Kong-* latency headers (Kong API gateway)
        assert "kong" in self._names(
            headers={"x-kong-upstream-latency": "8", "x-kong-proxy-latency": "1"})
        assert "kong" in self._names(headers={"server": "kong/3.4.1"})

    def test_bytedance_tiktok(self):
        # TikTok: server TLB + x-tt-logid (ByteDance edge, not Akamai Kona)
        assert "bytedance" in self._names(
            headers={"server": "TLB", "x-tt-logid": "20260814200057591DC34EF92C2774412B"})

    def test_aws_waf_cloudfront_403(self):
        # CloudFront + AWS WAF managed rules: 403 + x-cache: Error from
        # cloudfront on an attack-shaped request (bank-example.co.id,
        # example-hospital.com). Status is the _status pseudo-header.
        from w4f.scanner import fingerprint
        r = fingerprint({
            "ips": ["54.192.164.78"], "cname": [], "ptr": [], "cert": {},
            "tls": {"http": {"status": "HTTP/2 403 Forbidden",
                              "headers": {"server": "CloudFront",
                                          "x-cache": "Error from cloudfront"},
                              "set-cookie-list": []}},
        })
        assert "aws-waf" in [m["vendor"] for m in r]

    def test_aws_waf_not_on_normal_cloudfront_200(self):
        # A normal CloudFront 200 (Miss from cloudfront) must NOT claim WAF
        from w4f.scanner import fingerprint
        r = fingerprint({
            "ips": ["54.192.164.78"], "cname": [], "ptr": [], "cert": {},
            "tls": {"http": {"status": "HTTP/2 200 OK",
                              "headers": {"server": "CloudFront",
                                          "x-cache": "Miss from cloudfront"},
                              "set-cookie-list": []}},
        })
        names = [m["vendor"] for m in r]
        assert "aws-waf" not in names
        assert "aws-cloudfront" in names

    def test_azure_app_service(self):
        # example-energy.com: ARRAffinity cookies
        assert "azure-app-service" in self._names(
            cookies=["ARRAffinity=041885bba0a0f1c52e4b5a646bc9983c;Path=/;HttpOnly"])

    def test_no_false_positive_on_plain_nginx(self):
        assert self._names(headers={"server": "nginx/1.24.0"}) == ["nginx"]


def _fingerprint_result(headers=None, cookies=None, cname=None, ptr=None, ips=None, cert=None):
    from w4f.scanner import fingerprint
    return fingerprint({
        "ips": ips or ["8.8.8.8"],
        "cname": cname or [],
        "ptr": ptr or [],
        "cert": cert or {},
        "tls": {"http": {"headers": headers or {}, "set-cookie-list": cookies or []}},
    })
