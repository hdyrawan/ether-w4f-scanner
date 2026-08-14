"""Vendor signature table for ether-w4f-scanner.

Each vendor entry maps signature *kinds* to patterns:

    headers: {header_name_lower: regex-or-None}  (None = header presence enough)
    cookies: [regex, ...]                        against each Set-Cookie value
    cert:    regex against leaf issuer CN/O + subject CN/O (lowercased)
    cname:   regex against any CNAME in the chain (lowercased)
    ptr:     regex against any PTR of any resolved IP (lowercased)
    nets:    [ipnet, ...] the host's resolved IPs must fall inside

Written from scratch from publicly observed edge behaviour. Do not copy
detection rules verbatim from other WAF fingerprinting projects — several are
restrictively licensed.
"""

from __future__ import annotations

import ipaddress
import threading

VENDORS: dict[str, dict] = {
    "cloudflare": {
        "headers": {"server": r"cloudflare", "cf-ray": None, "cf-cache-status": None},
        "cookies": [r"^__cfduid=", r"^__cf_bm=", r"^_cfuvid="],
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
    "imperva": {
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
    "akamai": {
        "headers": {"server": r"akamai", "x-akamai": None, "x-akamai-transformed": None},
        "cookies": [r"^ak_bmsc=", r"^bm_sz=", r"^akavpau_", r"^_abck="],
        "cert": r"akamai",
        "cname": r"akamaized|akamaihd|edgesuite|akadns",
        "ptr": r"akamai",
        "nets": [
            "23.32.0.0/11", "104.64.0.0/10", "184.24.0.0/13",
            "2.16.0.0/13", "23.192.0.0/11", "96.6.0.0/15", "96.7.0.0/16",
        ],
    },
    "aws-cloudfront": {
        "headers": {"server": r"cloudfront", "x-amz-cf-id": None, "x-amz-cf-pop": None,
                    "x-cache": r"error from cloudfront", "via": r"cloudfront\.net"},
        "cname": r"cloudfront\.net",
        "ptr": r"cloudfront\.net",
        "nets": [
            "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14",
            "13.249.0.0/16", "18.160.0.0/15", "18.64.0.0/15",
            "52.84.0.0/15", "54.182.0.0/16", "99.84.0.0/16",
            "204.246.160.0/19", "205.251.192.0/19", "130.176.0.0/16",
        ],
    },
    "aws-waf": {
        "headers": {"x-amz-id": None, "x-amz-request-id": None,
                    "x-blocked-by-waf": r"awsmanagedrules|blocked_by_custom_response"},
        "cookies": [r"^aws\.?alb="],
    },
    "aws-elb": {
        "headers": {"server": r"awselb/2\.0"},
        "cname": r"elb\.amazonaws\.com",
        "ptr": r"compute\.amazonaws\.com",
    },
    "aws-s3": {
        "headers": {"server": r"amazons3", "x-amz-request-id": None},
        "cname": r"\.s3[.-].*\.amazonaws\.com",
    },
    "fastly": {
        "headers": {"server": r"fastly", "x-served-by": None, "x-timer": None,
                    "x-fastly-request-id": None, "via": r"fastly"},
        "cert": r"fastly",
        "cname": r"fastly\.net|fastlylb\.net",
        "ptr": r"fastly\.net",
        "nets": ["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16", "172.111.64.0/18"],
    },
    "azure-frontdoor": {
        "headers": {"x-azure-ref": None, "server": r"azure-frontdoor|frontdoor"},
        "cname": r"azurefd\.net",
        "ptr": r"azurefd\.net",
    },
    "azure-appgw": {
        "headers": {"server": r"microsoft-azure-application-gateway"},
    },
    "google-gfe": {
        "headers": {"server": r"gws|gfe|esf", "alt-svc": r"h3"},
        "cert": r"google trust services",
        "ptr": r"1e100\.net|googleusercontent\.com",
    },
    "f5": {
        "headers": {"server": r"bigip|big-ip", "x-wa-info": None, "x-cnection": None},
        # BIG-IP ASM / Advanced WAF sets the TS<hex> JavaScript-challenge
        # cookie; the hex run is 6-12 chars depending on build. BIGipServer
        # is the LTM persistence cookie, TSxxxx the ASM anti-bot cookie.
        "cookies": [r"^bigipserver", r"^MRHSession", r"^F5_", r"^TS[a-fA-F0-9]{6,12}="],
        "cert": r"f5 networks",
    },
    "netscaler": {
        "headers": {"server": r"ns_[a-z]|netscaler", "via": r"ns-cache",
                    "cneonction": None, "nncoection": None},
        "cookies": [r"^ns_af=", r"^citrix_ns_id", r"^NSC_"],
    },
    "sucuri": {
        "headers": {"server": r"sucuri", "x-sucuri-id": None, "x-sucuri-cache": None},
    },
    "stackpath": {
        "headers": {"server": r"stackpath"},
    },
    "openresty": {
        "headers": {"server": r"openresty"},
    },
    "nginx": {
        "headers": {"server": r"nginx(?:/|$)"},
    },
    "apache": {
        "headers": {"server": r"apache(?:/|$)"},
    },
    "envoy": {
        "headers": {"server": r"envoy", "x-envoy-upstream-service-time": None},
    },
    "haproxy": {
        "headers": {"server": r"haproxy"},
    },
    "caddy": {
        "headers": {"server": r"caddy"},
    },
    "litespeed": {
        "headers": {"server": r"litespeed"},
    },
    "varnish": {
        "headers": {"x-varnish": None, "via": r"varnish"},
        "cookies": [r"^cachewall"],
    },
    "arvancloud": {
        "headers": {"server": r"arvancloud", "x-arvan-*": None},
        "cname": r"arvan",
        "ptr": r"arvan",
    },
    "baidu-yunjiasu": {
        "headers": {"server": r"yunjiasu"},
    },
    "fortiweb": {
        "headers": {"server": r"fortiweb|fortigate"},
        "cookies": [r"^FORTIWAFSID="],
    },
    "modsecurity": {
        "headers": {"server": r"mod_security|modsecurity|noyb"},
    },
    "naxsi": {
        "headers": {"server": r"naxsi", "x-data-origin": r"naxsi"},
    },
    "wallarm": {
        "headers": {"server": r"nginx[_-]wallarm"},
    },
    "wordfence": {
        "headers": {"server": r"wf[_-]?waf"},
    },
    "zenedge": {
        "headers": {"server": r"zenedge", "x-zen-fury": None},
    },
    "zscaler": {
        "headers": {"server": r"zscaler"},
    },
    "ddos-guard": {
        "headers": {"server": r"ddos-guard"},
        "cookies": [r"^__ddg"],
    },
    "edgecast": {
        "headers": {"server": r"^ecd(?:/|$)|^ecs(?:/|$)", "x-ec-cache": None},
    },
    "maxcdn": {
        "headers": {"x-cdn": r"maxcdn"},
    },
    "keycdn": {
        "headers": {"server": r"keycdn"},
    },
    "barracuda": {
        "cookies": [r"^BNI__BARRACUDA_LB_COOKIE=", r"^barra_counter_session="],
    },
    "huawei-cloud-waf": {
        "headers": {"server": r"huaweicloudwaf"},
        "cookies": [r"^HWWAFSESID="],
    },
    "safedog": {
        "headers": {"server": r"safedog"},
        "cookies": [r"^safedog-flow-item="],
    },
}

# Header names that are interesting to SHOW even when they don't match a vendor.
INTERESTING_HEADERS = [
    "server", "via", "x-powered-by", "x-served-by", "x-cache",
    "x-cache-hits", "x-cache-status", "cf-ray", "cf-cache-status",
    "cf-connecting-ip", "x-iinfo", "x-cdn", "x-amz-cf-id", "x-amz-cf-pop",
    "x-amz-request-id", "x-azure-ref", "x-timer", "x-varnish", "x-wa-info",
    "x-cnection", "x-sucuri-id", "alt-svc", "strict-transport-security",
    "x-frame-options", "content-security-policy", "set-cookie", "location",
    "x-request-id", "x-correlation-id", "x-api-version", "x-ratelimit-*",
]

_NET_CACHE: dict[str, list] = {}
_NET_LOCK = threading.Lock()


def vendor_nets(name: str) -> list:
    """Compile a vendor's netblock strings once, thread-safely."""
    with _NET_LOCK:
        if name not in _NET_CACHE:
            _NET_CACHE[name] = [ipaddress.ip_network(n) for n in VENDORS[name].get("nets", [])]
    return _NET_CACHE[name]
