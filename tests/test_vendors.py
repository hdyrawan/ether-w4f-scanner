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
            rules.get(k) for k in ("headers", "cookies", "cert", "cname", "ptr",
                                   "nets", "block")
        )
        assert has_signal, f"vendor {name} has no usable signal kind"


def test_block_only_vendors_never_match_passively():
    """A vendor carrying ONLY a block rule (a middlebox on the scanner's own
    path) must be unreachable from the passive fingerprint loop — otherwise
    it would be reported as the target's edge."""
    from w4f.scanner import fingerprint
    passive_kinds = ("headers", "cookies", "cert", "cname", "ptr", "nets")
    block_only = [n for n, r in VENDORS.items()
                  if r.get("block") and not any(r.get(k) for k in passive_kinds)]
    assert block_only, "expected at least one block-only vendor"
    rich = {
        "ips": ["104.18.1.79"], "cname": ["x.edgekey.net"], "ptr": ["x.akamai.com"],
        "cert": {"issuer_org": "Fortinet", "issuer": "O=Fortinet"},
        "tls": {"http": {"headers": {"server": "nginx", "x-powered-by": "php"},
                         "set-cookie-list": ["cookiesession1=abc"]}},
    }
    matched = {m["vendor"] for m in fingerprint(rich)}
    for name in block_only:
        assert name not in matched, f"{name} must not match passively"


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
        assert rx.search("host.example.com.eo.dnse4.com")
        assert rx.search("foo.cdn.dnsv1.com.cn")


class TestNewSignatures:
    """Rules added from the 2026-08-14 internet accuracy sweep."""

    def _names(self, headers=None, cookies=None, **kw):
        return [m["vendor"] for m in _fingerprint_result(headers=headers, cookies=cookies, **kw)]

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

    def test_aws_global_accelerator(self):
        # resolves to AWS Global Accelerator ranges
        # (15.197.x / 3.33.x) with no elb.amazonaws.com CNAME.
        assert "aws-global-accelerator" in self._names(
            ips=["15.197.225.128", "3.33.251.168"])
        assert "aws-global-accelerator" in self._names(ips=["3.33.251.168"])
        assert "aws-global-accelerator" not in self._names(ips=["8.8.8.8"])

    def test_azure_frontdoor_config_nocache(self):
        # corporate Atlassian intranet hosts: x-cache CONFIG_NOCACHE with
        # hidden server header (Azure Front Door's cache-config marker).
        assert "azure-frontdoor" in self._names(
            headers={"x-cache": "CONFIG_NOCACHE"})
        assert "azure-frontdoor" in self._names(
            headers={"x-cache": "CONFIG_CACHE", "x-azure-ref": "ref"})

    def test_sgw_shopee_gateway(self):
        # bank UAT/staging: Server: SGW (Shopee/Sea Group API gateway)
        assert "sgw" in self._names(headers={"server": "SGW"})
        assert "sgw" in self._names(headers={"server": "SGW/1.0"})
        assert "sgw" not in self._names(headers={"server": "nginx"})

    def test_iis_origin(self):
        # mail/webmail/autodiscover hosts: plain Microsoft IIS origin
        assert "iis" in self._names(headers={"server": "Microsoft-IIS/10.0"})
        assert "iis" in self._names(headers={"server": "Microsoft-HTTPAPI/2.0"})
        assert "iis" not in self._names(headers={"server": "nginx"})

    def test_bytedance_tiktok(self):
        # TikTok: server TLB + x-tt-logid (ByteDance edge, not Akamai Kona)
        assert "bytedance" in self._names(
            headers={"server": "TLB", "x-tt-logid": "20260814200057591DC34EF92C2774412B"})

    def test_aws_waf_cloudfront_403(self):
        # CloudFront + AWS WAF managed rules: 403 + x-cache: Error from
        # cloudfront on an attack-shaped request (a bank's API host,
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

    def test_cloudflare_turnstile_cookies(self):
        # cf_turnstile_ / cf_chl_ cookies are Cloudflare challenge signals
        assert "cloudflare" in self._names(cookies=["cf_turnstile_abc=1; Path=/"])
        assert "cloudflare" in self._names(cookies=["cf_chl_opt=1; Path=/"])

    def test_cloudflare_waf_mitigated(self):
        # cf-mitigated: challenge is a managed-challenge/WAF verdict
        assert "cloudflare-waf" in self._names(
            headers={"cf-mitigated": "challenge"})
        assert "cloudflare-waf" in self._names(
            headers={"cf-mitigated": "blocked"})
        assert "cloudflare-waf" in self._names(
            cookies=["cf-waf-token=abc; Path=/"])

    def test_akamai_bot_manager_e3d_cookie(self):
        # ak_bmsc with an E3D tag inside the value = Bot Manager active
        assert "akamai" in self._names(cookies=[
            "ak_bmsc=0xABC~1AA;~_q=1;~e=2; E3D=15F0CD8D9A5C~_p=1"])
        # plain ak_bmsc without E3D still matches akamai via the first rule
        assert "akamai" in self._names(cookies=["ak_bmsc=0xABC~1AA;~_q=1"])

    def test_vercel(self):
        assert "vercel" in self._names(
            headers={"x-vercel-id": "sfo1::abc::123"},
            cname=["my-app.vercel.app"])
        assert "vercel" in self._names(headers={"server": "vercel"})

    def test_google_cloud_run(self):
        assert "google-cloud-run" in self._names(
            headers={"x-cloud-trace-context": "0123456789abcdef/1;o=1"})
        assert "google-cloud-run" in self._names(
            cname=["svc-abc-123.a.run.app"])

    def test_aws_app_runner(self):
        assert "aws-app-runner" in self._names(
            headers={"x-app-runner-region": "ap-southeast-3"})
        assert "aws-app-runner" in self._names(
            cname=["default.abc123.ap-southeast-3.awsapprunner.com"])

    def test_openresty_x_openresty_header(self):
        assert "openresty" in self._names(
            headers={"server": "openresty/1.21.4.1", "x-openresty": "1"})

    def test_fastly_waf_signal_sciences(self):
        assert "fastly-waf" in self._names(
            headers={"signal-attack": "1"},
            cookies=["__SignalShield_session=abc"])
        assert "fastly-waf" not in self._names(headers={"server": "fastly"})

    def test_akamai_delivery_cnames(self):
        # edgekey.net (Enhanced TLS) and akamaiedge.net (Standard TLS) are the
        # two most common Akamai delivery CNAMEs. Both were missed until
        # 0.1.34 — "akamai\.net" cannot match "akamaiedge.net" — which scored
        # an Akamai-fronted host headers-only, or unknown when the edge sent
        # no akamai-* header at all.
        assert "akamai" in self._names(cname=["www.example.com.edgekey.net"])
        assert "akamai" in self._names(cname=["example.com.akamaiedge.net"])
        assert "akamai" in self._names(cname=["a.example.com.edgekey-staging.net"])
        assert "akamai" in self._names(cname=["e1234.dscx.akamaiedge.net"])
        assert "akamai" in self._names(cname=["x.deploy.akamaitechnologies.com"])

    def test_akamai_cname_no_substring_false_positive(self):
        # a hostname that merely starts with "edgekey" is not Akamai
        assert "akamai" not in self._names(cname=["edgekeyless.example.com"])
        assert "akamai" not in self._names(cname=["cdn.example.net"])

    def test_akamai_cname_gives_real_confidence(self):
        # the point of the fix: cname(20) + headers(7) instead of headers(7)
        ver = _fingerprint_result(cname=["www.example.com.edgekey.net"],
                                  headers={"akamai-grn": "0.7ce0d58c.1786765563.216"})
        ak = next(m for m in ver if m["vendor"] == "akamai")
        assert ak["confidence"] == 27
        assert set(ak["categories"]) == {"cname", "headers"}

    def test_bytedance_no_akamaized_false_positive(self):
        # an Akamai customer CNAME must NOT claim bytedance
        assert "bytedance" not in self._names(cname=["cdn.example.akamaized.net"])
        assert "akamai" in self._names(cname=["cdn.example.akamaized.net"])
        # ByteDance-owned CNAME still matches
        assert "bytedance" in self._names(cname=["v16m.tiktokcdn.com"])

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


class TestDeployment:
    """cloud vs on-prem decides which interception route is possible at all:
    a cloud edge is anycast/SNI-routed with the origin elsewhere, an
    appliance sits on the origin's own address."""

    def test_values_are_valid(self):
        for name, rules in VENDORS.items():
            dep = rules.get("deployment")
            assert dep in (None, "cloud", "on-prem", "origin"), f"{name}: {dep}"

    def test_known_vendors_tagged(self):
        assert VENDORS["cloudflare"]["deployment"] == "cloud"
        assert VENDORS["akamai"]["deployment"] == "cloud"
        assert VENDORS["f5"]["deployment"] == "on-prem"
        assert VENDORS["netscaler"]["deployment"] == "on-prem"
        assert VENDORS["nginx"]["deployment"] == "origin"

    def test_dual_model_vendors_left_unset(self):
        # Imperva sells Incapsula (cloud) AND SecureSphere (on-prem); a
        # static tag would be wrong half the time, so the observed block
        # page carries it instead
        assert "deployment" not in VENDORS["imperva"]

    def test_verdict_carries_deployment(self):
        ver = _fingerprint_result(headers={"server": "cloudflare"},
                                  ips=["104.18.1.79"])
        cf = next(m for m in ver if m["vendor"] == "cloudflare")
        assert cf["deployment"] == "cloud"

    def test_block_page_reports_the_variant(self):
        from w4f.scanner import match_block_page
        on_prem = match_block_page(
            "Error", "", "the incident id is: 5. contact support for "
            "additional information.", "HTTP/1.1 200 OK")
        assert on_prem["vendor"] == "imperva" and on_prem["deployment"] == "on-prem"
        cloud = match_block_page("Access Denied", "",
                                 "incapsula incident id", "HTTP/1.1 403 Forbidden")
        assert cloud["vendor"] == "imperva" and cloud["deployment"] == "cloud"


class TestBlockRulesAreModular:
    def test_block_rules_live_in_vendor_files(self):
        # adding a block page must not require editing the matcher
        names = {n for n, r in VENDORS.items() if r.get("block")}
        assert {"fortiweb", "f5", "imperva", "cloudflare", "akamai"} <= names

    def test_priority_orders_specific_before_generic(self):
        from w4f.scanner import _block_rules
        order = [n for n, _ in _block_rules()]
        # the interception page must be evaluated before any vendor page
        assert order[0] == "fortinet-webfilter"
        # aws-waf's CloudFront-error rule is the most generic — evaluated last
        assert order[-1] == "aws-waf"

    def test_reported_vendor_name_can_be_overridden(self):
        from w4f.scanner import match_block_page
        out = match_block_page("Request Rejected", "", "support id", "HTTP/1.1 200 OK")
        assert out["vendor"] == "f5-asm"   # not the signature name "f5"
