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

    def test_wso2_carbon_server_header(self):
        # WSO2 Carbon products set server="WSO2 Carbon Server" in their own
        # Tomcat config (product-is / product-apim catalina-server.xml)
        r = _result(headers={"server": "WSO2 Carbon Server"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "wso2" in names
        assert "nginx" not in names

    def test_wso2_x_wso2_prefix_header(self):
        # any x-wso2-* response header is a WSO2 marker (prefix match)
        r = _result(headers={"x-wso2-api-id": "abcdef", "server": "nginx"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "wso2" in names

    def test_wso2_does_not_fire_on_plain_nginx(self):
        r = _result(headers={"server": "nginx/1.24.0"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "wso2" not in names
        assert "nginx" in names

    def test_cloudflare_mapi_example(self):
        r = _result(
            ips=["104.18.1.79"],
            cname=["api.example.bank.cdn.cloudflare.net"],
            headers={"server": "cloudflare", "cf-ray": "abc-CGK",
                     "cf-cache-status": "DYNAMIC"},
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "cloudflare" in names

    def test_tencent_edgeone_cname(self):
        r = _result(
            ips=["43.174.196.219"],
            cname=["host.example.com.eo.dnse4.com"],
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

    def test_bare_403_not_aws_waf(self):
        # A 403 with no AWS marker (Cloudflare challenge, nginx deny) must
        # NOT claim aws-waf — the requires gate needs an AWS-specific marker.
        r = _result(headers={"server": "nginx", "_status": "403"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "aws-waf" not in names
        assert "nginx" in names

    def test_403_with_cloudfront_cache_is_aws_waf(self):
        # CloudFront + AWS WAF shape: 403 AND x-cache error-from-cloudfront.
        r = _result(headers={"server": "CloudFront", "_status": "403",
                             "x-cache": "Error from cloudfront"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "aws-waf" in names

    def test_cloudflare_challenge_403_not_aws_waf(self):
        # berkeley.edu case from the big sweep: cf-mitigated challenge + 403
        # is Cloudflare, not AWS.
        r = _result(
            headers={"server": "cloudflare", "cf-mitigated": "challenge", "_status": "403"},
            cookies=["__cf_bm=abc"],
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "aws-waf" not in names
        assert "cloudflare" in names

    def test_gts_cert_alone_not_google_gfe(self):
        # Cloudflare hosts use Google Trust Services certs — a GTS issuer
        # alone must NOT phantom google-gfe (requires server/PTR gate).
        r = _result(
            ips=["104.16.1.1"],
            headers={"server": "cloudflare", "cf-ray": "abc"},
            cert={"issuer_org": "Google Trust Services", "subject_org": "Cloudflare, Inc."},
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "google-gfe" not in names
        assert "cloudflare" in names

    def test_gfe_server_header_is_google(self):
        # Server: gws is the decisive google-gfe signal even with a GTS cert.
        r = _result(
            ips=["34.36.226.141"],
            headers={"server": "gws"},
            cert={"issuer_org": "Google Trust Services"},
        )
        assert "google-gfe" in [m["vendor"] for m in fingerprint(r)]

    def test_gfe_ptr_is_google_origin(self):
        # A Google Cloud origin PTR behind a Cloudflare edge is a REAL
        # multi-layer answer (linkedin/tiket in the big sweep), not noise.
        r = _result(
            ips=["14.32.211.130"],
            ptr=["14.32.211.130.bc.googleusercontent.com"],
            headers={"server": "cloudflare", "cf-ray": "abc"},
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "cloudflare" in names
        assert "google-gfe" in names

    def test_x_served_by_marketing_site_not_fastly(self):
        # cloudflare.com case from the big sweep: "x-served-by:
        # marketing-site" is Cloudflare's own marker, not Fastly.
        r = _result(
            ips=["104.16.133.229"],
            headers={"server": "cloudflare", "cf-ray": "abc",
                     "x-served-by": "marketing-site"},
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "fastly" not in names
        assert "cloudflare" in names

    def test_x_served_by_cache_node_is_fastly(self):
        # Real Fastly cache node naming (x-served-by: cache-<po>).
        r = _result(
            ips=["151.101.0.81"],
            headers={"x-served-by": "cache-sin-wsap440094-SIN",
                     "x-timer": "S1786724063.140005,VS0,VE4"},
        )
        assert "fastly" in [m["vendor"] for m in fingerprint(r)]

    def test_squarespace_platform(self):
        # Squarespace managed platform serves `server: Squarespace`.
        r = _result(headers={"server": "Squarespace"})
        assert "squarespace" in [m["vendor"] for m in fingerprint(r)]

    def test_datadome(self):
        r = _result(headers={"x-datadome": "blocked"},
                    cookies=["datadome=abcd1234; Path=/"])
        assert "datadome" in [m["vendor"] for m in fingerprint(r)]

    def test_perimeterx(self):
        r = _result(cookies=["_pxhd=abc123; Path=/"])
        assert "perimeterx" in [m["vendor"] for m in fingerprint(r)]

    def test_kasada_cookie(self):
        r = _result(cookies=["kpsdk_ct=abc123; Path=/"])
        assert "kasada" in [m["vendor"] for m in fingerprint(r)]

    def test_shape_security(self):
        r = _result(cookies=["shape_1221=abc; Path=/"])
        assert "shape-security" in [m["vendor"] for m in fingerprint(r)]

    def test_arkose_cookie(self):
        r = _result(cookies=["arkose_token=abc; Path=/"])
        assert "arkose" in [m["vendor"] for m in fingerprint(r)]

    def test_reblaze(self):
        r = _result(headers={"x-reblaze-cache": "HIT"},
                    cookies=["rbzid=abc; Path=/"])
        assert "reblaze" in [m["vendor"] for m in fingerprint(r)]

    def test_radware(self):
        r = _result(cookies=["mpev_1258=abc; Path=/"])
        assert "radware" in [m["vendor"] for m in fingerprint(r)]

    def test_tyk_prefix_header(self):
        # x-tyk-* prefix match: x-tyk-request-id is a real Tyk header.
        r = _result(headers={"x-tyk-request-id": "abc123"})
        assert "tyk" in [m["vendor"] for m in fingerprint(r)]

    def test_apigee_prefix_header(self):
        r = _result(headers={"apigee-request-id": "abc"})
        assert "apigee" in [m["vendor"] for m in fingerprint(r)]

    def test_azure_api_management(self):
        r = _result(headers={"ocp-apim-subscription-key": "deadbeef"},
                    cname=["api.example.azure-api.net"])
        assert "azure-api-management" in [m["vendor"] for m in fingerprint(r)]

    def test_cloudflare_workers(self):
        r = _result(headers={"server": "cloudflare", "cf-worker": "router"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "cloudflare-workers" in names
        assert "cloudflare" in names  # base vendor fires too

    def test_gcp_armor(self):
        r = _result(headers={"x-goog-generate-id": "12345"})
        assert "gcp-armor" in [m["vendor"] for m in fingerprint(r)]

    def test_prefix_glob_does_not_fire_on_unrelated_header(self):
        # a header literally named "x-tyk-" (with the asterisk missing) must
        # not match — the prefix rule is anchored to the real prefix
        r = _result(headers={"x-tykfoo": "abc"})
        assert "tyk" not in [m["vendor"] for m in fingerprint(r)]


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

    def test_confidence_high_with_netblock_cert_cname(self):
        # Cloudflare: netblock(30) + cert(25) + cname(20) + headers(7) = 82
        r = _result(
            ips=["104.18.1.79"],
            cname=["x.example.com.cdn.cloudflare.net"],
            headers={"server": "cloudflare", "cf-ray": "abc"},
            cert={"issuer_org": "Cloudflare, Inc.", "subject_org": "Cloudflare, Inc."},
        )
        ver = fingerprint(r)
        cf = next(m for m in ver if m["vendor"] == "cloudflare")
        assert cf["confidence"] == 82

    def test_confidence_low_for_single_header(self):
        # nginx single Server header = headers(7) only
        ver = fingerprint(_result(headers={"server": "nginx"}))
        assert ver == [{"vendor": "nginx", "signals": 1, "confidence": 7,
                        "evidence": ["header server: nginx"]}]

    def test_confidence_capped_at_100(self):
        # A vendor with all six categories matched cannot exceed 100 even
        # with multiple headers/cookies (each category counted once).
        r = _result(
            ips=["104.18.1.79"],
            cname=["x.example.com.cdn.cloudflare.net"],
            ptr=["x.example.com.cdn.cloudflare.net"],
            headers={"server": "cloudflare", "cf-ray": "abc", "cf-cache-status": "DYNAMIC"},
            cookies=["__cf_bm=abc", "_cfuvid=xyz"],
            cert={"issuer_org": "Cloudflare, Inc.", "subject_org": "Cloudflare, Inc."},
        )
        ver = fingerprint(r)
        cf = next(m for m in ver if m["vendor"] == "cloudflare")
        assert cf["confidence"] == 100

    def test_confidence_signal_count_still_primary_sort(self):
        # Two vendors, one with more signals: signals sort first, confidence
        # is a tiebreak field only.
        r = _result(
            ips=["104.18.1.79"],
            headers={"server": "cloudflare", "cf-ray": "abc"},
            cert={"issuer_org": "Cloudflare, Inc."},
        )
        ver = fingerprint(r)
        assert ver[0]["vendor"] == "cloudflare"
        # both fields present on every match
        for m in ver:
            assert "signals" in m and "confidence" in m

    def test_cloudfront_jakarta_netblock_fires(self):
        # EXAMPLE_BANK case: 3.168.x.x (Jakarta CloudFront edge) must hit the
        # netblock category — it was missing from the table before, leaving
        # a PTR-confirmed CloudFront host at 22% instead of 52%.
        r = _result(
            ips=["3.168.203.66", "3.168.203.9"],
            ptr=["server-3-168-203-66.cgk51.r.cloudfront.net"],
            headers={"server": "CloudFront", "x-amz-cf-pop": "CGK51-P4",
                     "via": "1.1 abc.cloudfront.net (CloudFront)"},
        )
        ver = fingerprint(r)
        cf = next(m for m in ver if m["vendor"] == "aws-cloudfront")
        assert any(e.startswith("netblock:") for e in cf["evidence"])
        assert cf["confidence"] == 52  # netblock 30 + headers 7 + ptr 15

    def test_evidence_strings_present(self):
        r = _result(cookies=["TS01538524=012b5961782784783de7052afa3b4817"])
        ver = fingerprint(r)
        assert any("cookie: TS" in e for m in ver for e in m["evidence"])


class TestChineseEdges:
    """Positive + negative cases for the Chinese CDN/WAF vendors added from
    the 2026-08-14 internet-wide + China sweep (v0.1.29)."""

    def test_jiasule_x_via_jsl(self):
        r = _result(headers={"x-via-jsl": "0fedc55,-", "x-cache": "bypass"})
        assert "jiasule" in [m["vendor"] for m in fingerprint(r)]

    def test_jiasule_cookie(self):
        r = _result(cookies=["__jsluid_s=54c8295839ec594de6117d89652ab6fc; path=/"])
        assert "jiasule" in [m["vendor"] for m in fingerprint(r)]

    def test_jiasule_cname(self):
        r = _result(cname=["edge.vip.jiasule.org"])
        assert "jiasule" in [m["vendor"] for m in fingerprint(r)]

    def test_wswaf_server(self):
        r = _result(headers={"server": "wswaf"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "wswaf" in names
        assert "nginx" not in names

    def test_knownsec_cname(self):
        r = _result(cname=["host.cname.365cyd.cn"])
        assert "knownsec" in [m["vendor"] for m in fingerprint(r)]

    def test_wangsu_cname(self):
        r = _result(cname=["host.example.com.wscdns.com"])
        assert "wangsu" in [m["vendor"] for m in fingerprint(r)]

    def test_wangsu_uproxy_via(self):
        r = _result(headers={"via": "1.1 ID-17166357503 uproxy-21"})
        assert "wangsu" in [m["vendor"] for m in fingerprint(r)]

    def test_wangsu_does_not_fire_on_chinacache(self):
        # ChinaCache hosts share the (Cdn Cache Server V2.0) via marker but
        # CNAME to lxdns.com — the CNAME must decide, not the shared marker.
        r = _result(
            cname=["host.example.com.lxdns.com"],
            headers={"x-via": "1.1 PS-CGK-04VSI108:34 (Cdn Cache Server V2.0)"},
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "chinacache" in names
        assert "wangsu" not in names

    def test_chinacache_cname(self):
        r = _result(cname=["cdn.example.com.lxdns.com"])
        assert "chinacache" in [m["vendor"] for m in fingerprint(r)]

    def test_aliyun_cname(self):
        r = _result(cname=["host.example.com.tbcache.com"])
        assert "aliyun" in [m["vendor"] for m in fingerprint(r)]

    def test_aliyun_kunlun_cname(self):
        # kunlun*.com = Alibaba CDN (昆仑) — www.gold678.com.w.kunlunca.com
        r = _result(cname=["cdn.example.com.w.kunlunca.com"])
        assert "aliyun" in [m["vendor"] for m in fingerprint(r)]

    def test_360panyun_server(self):
        r = _result(headers={"server": "panyun"})
        assert "360panyun" in [m["vendor"] for m in fingerprint(r)]

    def test_360panyun_cname(self):
        r = _result(cname=["edge.360panyun.com"])
        assert "360panyun" in [m["vendor"] for m in fingerprint(r)]

    def test_aliyun_esa_cookie(self):
        r = _result(cookies=["acw_tc=a3b59eaf...;path=/;HttpOnly"])
        assert "aliyun" in [m["vendor"] for m in fingerprint(r)]

    def test_aliyun_yunfeng_cookie(self):
        # aliyungf_tc = Alibaba Cloud WAF (云盾) visitor cookie
        r = _result(cookies=["aliyungf_tc=f8dc0669d0cd8e6e4a6abd5ca155b193e11b2af1aec0a4ca9bcc35a36075e8b6; Path=/; HttpOnly"])
        assert "aliyun" in [m["vendor"] for m in fingerprint(r)]

    def test_aliyun_eagleeye_header(self):
        r = _result(headers={"eagleeye-traceid": "2100c81c17867323955146733ed0b1"})
        assert "aliyun" in [m["vendor"] for m in fingerprint(r)]

    def test_aliyun_does_not_fire_on_netease(self):
        # NetEase's CDN also emits the ens-cache via marker — cname is the
        # distinguishing signal, not the via string.
        r = _result(
            cname=["www.example.com.163jiasu.com"],
            headers={"server": "Tengine", "via": "ens-cache9.id62[,403011]"},
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "netease" in names
        assert "aliyun" not in names

    def test_netscaler_does_not_fire_on_ens_cache(self):
        # ens-cache (Alibaba/NetEase edge) must NOT match the netscaler
        # ns-cache via regex — a substring match shipped a false verdict on
        # major Alibaba/NetEase-fronted sites.
        r = _result(
            headers={"server": "Tengine",
                     "via": "ens-cache15.l2id3[0,0,304-0,H], ens-cache12.l2id3[1,0]"},
        )
        names = [m["vendor"] for m in fingerprint(r)]
        assert "netscaler" not in names

    def test_volcengine_server(self):
        r = _result(headers={"server": "volc-dcdn", "age": "31"})
        assert "volcengine" in [m["vendor"] for m in fingerprint(r)]

    def test_volcengine_vedcdnlb_cname(self):
        r = _result(cname=["cdn.example.com.c.vedcdnlb.com"])
        assert "volcengine" in [m["vendor"] for m in fingerprint(r)]

    def test_qiniu_cname(self):
        r = _result(cname=["cdn.example.com.qiniudns.com"])
        assert "qiniu" in [m["vendor"] for m in fingerprint(r)]

    def test_huawei_cloud_cdn_cname(self):
        r = _result(cname=["cdn.example.com.c.cdnhwc1.com"])
        assert "huawei-cloud-cdn" in [m["vendor"] for m in fingerprint(r)]

    def test_huawei_cloud_cdn_headers(self):
        r = _result(headers={"x-ccdn-expires": "58", "x-hcs-proxy-type": "1"})
        assert "huawei-cloud-cdn" in [m["vendor"] for m in fingerprint(r)]

    def test_baidu_cdn_header(self):
        r = _result(headers={"x-bdcdn-cache-status": "TCP_MISS,TCP_MISS"})
        assert "baidu-cdn" in [m["vendor"] for m in fingerprint(r)]

    def test_baidu_cdn_via(self):
        r = _result(headers={"via": "n62-196-017.bdcdn-CN-HK-HKG3.ToB"})
        assert "baidu-cdn" in [m["vendor"] for m in fingerprint(r)]

    def test_baidu_bfe_server(self):
        r = _result(headers={"server": "bfe/1.0.8.18"})
        assert "baidu-bfe" in [m["vendor"] for m in fingerprint(r)]

    def test_baidu_bfe_cname(self):
        r = _result(cname=["host.a.shifen.com"])
        assert "baidu-bfe" in [m["vendor"] for m in fingerprint(r)]

    def test_baidu_bfe_does_not_fire_on_origin_apache(self):
        # A Baidu property GET can echo the search BFF's `apache` — that is
        # the origin layer, not the edge; no shifen CNAME means no bfe verdict.
        r = _result(headers={"server": "apache", "x-hit-search-bff": "1"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert "baidu-bfe" not in names
        assert "apache" in names

    def test_baishan_cname(self):
        r = _result(cname=["www.example.com.bsgslb.cn"])
        assert "baishan" in [m["vendor"] for m in fingerprint(r)]

    def test_netease_cname(self):
        r = _result(cname=["www.example.com.163jiasu.com"])
        assert "netease" in [m["vendor"] for m in fingerprint(r)]

    def test_bytedance_bytedns1_cname(self):
        r = _result(cname=["www.example.com.bytedns1.com"])
        assert "bytedance" in [m["vendor"] for m in fingerprint(r)]

    def test_plain_nginx_fires_no_new_vendors(self):
        r = _result(headers={"server": "nginx/1.24.0"})
        names = [m["vendor"] for m in fingerprint(r)]
        assert names == ["nginx"]

    def test_qrator_server(self):
        r = _result(headers={"server": "QRATOR"})
        assert "qrator" in [m["vendor"] for m in fingerprint(r)]

    def test_360wangzhanbao_wzws_header(self):
        r = _result(headers={"wzws-ray": "002-1786734657.007-cache02fst-waf04fst"})
        assert "360wangzhanbao" in [m["vendor"] for m in fingerprint(r)]

    def test_360wangzhanbao_cname(self):
        r = _result(cname=["0417861b351234d9.qaxcloudwaf.com"])
        assert "360wangzhanbao" in [m["vendor"] for m in fingerprint(r)]

    def test_variti_server(self):
        r = _result(headers={"server": "Variti/0.9.3a"})
        assert "variti" in [m["vendor"] for m in fingerprint(r)]

    def test_uewaf_server(self):
        r = _result(headers={"server": "uewaf/4.0.5"})
        assert "uewaf" in [m["vendor"] for m in fingerprint(r)]

    def test_airee_server(self):
        r = _result(headers={"server": "Airee/Cloud"})
        assert "airee" in [m["vendor"] for m in fingerprint(r)]

    def test_airee_cookie(self):
        r = _result(cookies=["airee_visitor=1; path=/"])
        assert "airee" in [m["vendor"] for m in fingerprint(r)]

    def test_jd_cloud_cname(self):
        r = _result(cname=["www.example.com.s.galileo.jcloud-cdn.com"])
        assert "jd-cloud" in [m["vendor"] for m in fingerprint(r)]

    def test_jd_cloud_qianxun_cname(self):
        r = _result(cname=["www.example.com.gslb.qianxun.com"])
        assert "jd-cloud" in [m["vendor"] for m in fingerprint(r)]

    def test_azion_prefix_header(self):
        r = _result(headers={"x-azion-request-id": "e217d28c248bfb33391a838b4424599f",
                             "x-azion-edge-location": "MIA"})
        assert "azion" in [m["vendor"] for m in fingerprint(r)]
