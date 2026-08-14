"""CDN / edge vendors (24).

Each entry is a vendor dict per the modular signature schema
(see _template.py). One file per vendor is also fine — this file just groups
the CDN/edge family together for readability.
"""

VENDORS = [
    {
        "name": "cloudflare",
        "headers": {"server": r"cloudflare", "cf-ray": None, "cf-cache-status": None,
                    # Turnstile / challenge / managed-challenge mitigation
                    "cf-mitigated": r"challenge|blocked"},
        "cookies": [r"^__cfduid=", r"^__cf_bm=", r"^_cfuvid=",
                    r"^cf_chl_", r"^cf_turnstile_"],
        "cert": r"cloudflare",
        "cname": r"cloudflare",
        "ptr": r"cloudflare",
        "nets": [
            "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
            "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
            "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
            "162.158.0.0/15", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "2400:cb00::/32", "2606:4700::/32",
            "2803:f800::/32", "2c0f:f248::/32",
        ],
    },
    {
        "name": "cloudflare-waf",
        # Cloudflare WAF / Bot Management: challenge or block verdicts that
        # CDN-only hosts never emit. cf-mitigated is emitted by the managed
        # challenge/Turnstile path; the cf_chl_/cf-waf-token cookies and
        # cf-chl-bypass header belong to the JS-challenge flow.
        "headers": {"cf-mitigated": r"challenge|blocked", "cf-chl-bypass": None,
                    "cf-waf-rule-id": None},
        "cookies": [r"^__cf_bm=", r"^cf-waf-token=", r"^cf_chl_"],
    },
    {
        "name": "imperva",
        "headers": {"x-iinfo": None, "x-cdn": r"incap", "server": r"imperva"},
        "cookies": [r"^incap_ses", r"^visid_incap", r"^incap_visid_"],
        "cert": r"imperva",
        "cname": r"incapdns|impervadns",
        "ptr": r"incap|imperva",
        "nets": [
            "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21",
            "103.21.244.0/22", "45.64.64.0/22", "185.11.124.0/22",
            "192.230.64.0/18", "107.154.0.0/16", "45.60.0.0/16",
            "45.223.0.0/16", "2a02:e980::/29",
        ],
    },
    {
        "name": "akamai",
        "headers": {"server": r"akamai", "x-akamai": None, "x-akamai-transformed": None,
                    # Kona WAF signals: AkamaiGHost server + request-tracking headers
                    "akamai-grn": None, "x-grn": None, "akamai-request-bc": None},
        "cookies": [r"^ak_bmsc=", r"^bm_sz=", r"^akavpau_", r"^_abck=",
                    r"^aka~", r"^akaalb_",
                    # Bot Manager E3D tag inside the ak_bmsc cookie value
                    r"^ak_bmsc=[^;]*;\s*.*\bE3D="],
        "cert": r"akamai",
        "cname": r"akamaized|akamaihd|edgesuite|akadns|akamai\.net",
        "ptr": r"akamai",
        "nets": [
            "23.32.0.0/11", "104.64.0.0/10", "184.24.0.0/13",
            "2.16.0.0/13", "23.192.0.0/11", "96.6.0.0/15", "96.7.0.0/16",
        ],
    },
    {
        "name": "aws-cloudfront",
        "headers": {"server": r"cloudfront", "x-amz-cf-id": None, "x-amz-cf-pop": None,
                    "x-cache": r"error from cloudfront", "via": r"cloudfront\.net"},
        "cname": r"cloudfront\.net",
        "ptr": r"cloudfront\.net",
        # Coarse AWS-published CLOUDFRONT ranges (3.160/3.168/108.156 are the
        # large /14s missing from the earlier table — 3.168 covers the Jakarta
        # edge that serves .co.id hosts; PTR already confirms it).
        "nets": [
            "3.160.0.0/14", "3.168.0.0/14", "13.32.0.0/15", "13.35.0.0/16",
            "13.224.0.0/14", "13.249.0.0/16", "18.160.0.0/15", "18.64.0.0/15",
            "52.84.0.0/15", "54.182.0.0/16", "99.84.0.0/16",
            "108.156.0.0/14", "130.176.0.0/16", "204.246.160.0/19",
            "205.251.192.0/19",
        ],
    },
    {
        "name": "aws-waf",
        # Two shapes: (1) ALB/API-GW WAF headers (x-amz-* / x-blocked-by-waf),
        # (2) CloudFront + AWS WAF managed rules — the edge answers 403 with
        # "x-cache: Error from cloudfront" on an attack-shaped request.
        # The status is exposed as the pseudo-header _status by fingerprint().
        # requires: a bare 403 (Cloudflare challenge, nginx deny, ...) must
        # NOT claim aws-waf — at least one AWS-specific marker must co-occur.
        "headers": {"x-amz-id": None, "x-amz-request-id": None,
                    "x-blocked-by-waf": r"awsmanagedrules|blocked_by_custom_response",
                    "_status": r"403", "x-cache": r"^error from cloudfront$"},
        "cookies": [r"^aws\.?alb="],
        "requires": [
            # CloudFront + AWS WAF shape: 403 AND the error-from-cloudfront
            # cache marker must co-occur (a bare 403 is not enough).
            [{"kind": "header", "name": "_status", "re": r"403"},
             {"kind": "header", "name": "x-cache", "re": r"error from cloudfront"}],
            # ALB/API-GW WAF shape: any AWS WAF marker header is enough.
            {"kind": "header", "name": "x-amz-id"},
            {"kind": "header", "name": "x-amz-request-id"},
            {"kind": "header", "name": "x-blocked-by-waf"},
        ],
    },
    {
        "name": "aws-elb",
        "headers": {"server": r"awselb/2\.0"},
        "cname": r"elb\.amazonaws\.com",
        "ptr": r"compute\.amazonaws\.com",
    },
    {
        "name": "aws-global-accelerator",
        # AWS Global Accelerator (GLOBALACCELERATOR ranges from
        # ip-ranges.amazonaws.com). Serves an AWS edge without the
        # elb.amazonaws.com CNAME; found on a corporate website that
        # resolves to 15.197.x / 3.33.x, PTR *.awsglobalaccelerator.com,
        # and 301s to its portal from ip-*.eu-west-2.compute.internal.
        "nets": ["15.197.0.0/16", "3.33.0.0/16"],
        "ptr": r"awsglobalaccelerator\.com",
    },
    {
        "name": "aws-s3",
        "headers": {"server": r"amazons3", "x-amz-request-id": None},
        "cname": r"\.s3[.-].*\.amazonaws\.com",
    },
    {
        "name": "aws-ec2",
        # Bare EC2 origin (no managed edge): PTR is ec2-…compute-N.amazonaws.com.
        # Not a WAF/CDN — but the answer "plain AWS origin, no edge" matters.
        "ptr": r"compute-\d+\.amazonaws\.com",
    },
    {
        "name": "fastly",
        # x-served-by must look like a Fastly cache node (cache-<po>) — mere
        # presence is not enough: Cloudflare's own marketing site sends
        # "x-served-by: marketing-site" and would phantom fastly.
        "headers": {"server": r"fastly", "x-served-by": r"cache-", "x-timer": None,
                    "x-fastly-request-id": None, "via": r"fastly"},
        "cert": r"fastly",
        "cname": r"fastly\.net|fastlylb\.net",
        "ptr": r"fastly\.net",
        "nets": ["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16", "172.111.64.0/18"],
    },
    {
        "name": "fastly-waf",
        # Fastly Next-Gen WAF (formerly Signal Sciences): distinct debug
        # header + SignalShield cookie from the plain CDN layer.
        "headers": {"fastly-waf-debug": None, "signal-attack": None},
        "cookies": [r"^__SignalShield_"],
    },
    {
        "name": "azure-frontdoor",
        # CONFIG_NOCACHE x-cache value is Front Door's own cache config
        # marker (seen on corporate Atlassian intranet hosts with no
        # x-azure-ref and a hidden server header).
        "headers": {"x-azure-ref": None, "server": r"azure-frontdoor|frontdoor",
                    "x-cache": r"CONFIG_NOCACHE|CONFIG_CACHE"},
        "cname": r"azurefd\.net",
        "ptr": r"azurefd\.net",
    },
    {
        "name": "azure-appgw",
        "headers": {"server": r"microsoft-azure-application-gateway"},
    },
    {
        "name": "arvancloud",
        # Header keys are matched by EXACT lookup, not glob, so a wildcard
        # key like "x-arvan-*" never fires. Use the concrete header
        # ArvanCloud actually sends (x-arvan-request-id).
        "headers": {"server": r"arvancloud", "x-arvan-request-id": None},
        "cname": r"arvan",
        "ptr": r"arvan",
    },
    {
        "name": "tencent-edgeone",
        # Tencent EdgeOne (international CDN/WAF, ex-CDN solution). Decisive:
        # the `eo-log-uuid` response header and the `eo.dnse4.com` CNAME.
        # Observed on a bank's EdgeOne-fronted host (2026-08-14): CNAME
        # host.example.com.eo.dnse4.com, header `eo-log-uuid`, HTTP 567
        # on bare GET. Tencent Cloud CDN (mainland) uses *.cdn.dnsv1.com.cn.
        "headers": {"eo-log-uuid": None, "eo-cache-status": None, "server": r"edgeone|tencent"},
        "cname": r"eo\.dnse4\.com|edgeone|dnsv1\.com|tencentcs\.com|tcdn",
        "ptr": r"edgeone|dnse4|dnsv1",
    },
    {
        "name": "tencent-cdn",
        "headers": {"server": r"tencent", "x-cache-lookup": None},
        "cname": r"dnsv1\.com(\.cn)?|tencentcs\.com|\.tcdn\.",
    },
    {
        "name": "baidu-yunjiasu",
        "headers": {"server": r"yunjiasu"},
    },
    {
        "name": "edgecast",
        "headers": {"server": r"^ecd(?:/|$)|^ecs(?:/|$)", "x-ec-cache": None},
    },
    {
        "name": "maxcdn",
        "headers": {"x-cdn": r"maxcdn"},
    },
    {
        "name": "keycdn",
        "headers": {"server": r"keycdn"},
    },
    {
        "name": "stackpath",
        "headers": {"server": r"stackpath"},
    },
    {
        "name": "zenedge",
        "headers": {"server": r"zenedge", "x-zen-fury": None},
    },
    {
        "name": "ddos-guard",
        "headers": {"server": r"ddos-guard"},
        "cookies": [r"^__ddg"],
    },
]
