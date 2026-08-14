"""WAF / protection vendors (16).

Each entry is a vendor dict per the modular signature schema
(see _template.py). One file per vendor is also fine — this file just groups
the WAF/protection family together for readability.
"""

VENDORS = [
    {
        "name": "fortiweb",
        "headers": {"server": r"fortiweb|fortigate"},
        "cookies": [r"^FORTIWAFSID="],
    },
    {
        "name": "modsecurity",
        "headers": {"server": r"mod_security|modsecurity|noyb"},
    },
    {
        "name": "naxsi",
        "headers": {"server": r"naxsi", "x-data-origin": r"naxsi"},
    },
    {
        "name": "wallarm",
        "headers": {"server": r"nginx[_-]wallarm"},
    },
    {
        "name": "wordfence",
        "headers": {"server": r"wf[_-]?waf"},
    },
    {
        "name": "huawei-cloud-waf",
        "headers": {"server": r"huaweicloudwaf"},
        "cookies": [r"^HWWAFSESID="],
    },
    {
        "name": "safedog",
        "headers": {"server": r"safedog"},
        "cookies": [r"^safedog-flow-item="],
    },
    {
        "name": "barracuda",
        "cookies": [r"^BNI__BARRACUDA_LB_COOKIE=", r"^barra_counter_session="],
    },
    {
        "name": "sucuri",
        "headers": {"server": r"sucuri", "x-sucuri-id": None, "x-sucuri-cache": None},
    },
    {
        "name": "zscaler",
        "headers": {"server": r"zscaler"},
    },
    {
        "name": "gcp-armor",
        # Google Cloud Armor: x-goog-* headers on 4xx/5xx from the edge.
        "headers": {"x-goog-*": None, "server": r"gcloud|gfe.*armor"},
    },
    {
        "name": "radware",
        # Radware WAF/AppWall: mpev_* cookies + x-radware headers.
        "headers": {"x-radware-*": None, "server": r"radware|appwall"},
        "cookies": [r"^mpev_"],
    },
    {
        "name": "reblaze",
        # Reblaze WAF: x-reblaze-* headers + rbzid cookie.
        "headers": {"x-reblaze-*": None, "server": r"reblaze"},
        "cookies": [r"^rbzid="],
    },
    {
        "name": "f5",
        "headers": {"server": r"bigip|big-ip", "x-wa-info": None, "x-cnection": None},
        # BIG-IP ASM / Advanced WAF sets the TS<hex> JavaScript-challenge
        # cookie; the hex run is 6-12 chars depending on build. BIGipServer
        # is the LTM persistence cookie, TSxxxx the ASM anti-bot cookie.
        "cookies": [r"^bigipserver", r"^MRHSession", r"^F5_", r"^TS[a-fA-F0-9]{6,12}="],
        "cert": r"f5 networks",
    },
    {
        "name": "netscaler",
        "headers": {"server": r"ns_[a-z]|netscaler", "via": r"ns-cache",
                    "cneonction": None, "nncoection": None},
        "cookies": [r"^ns_af=", r"^citrix_ns_id", r"^NSC_"],
    },
    {
        "name": "gtm-gslb",
        # DNS-level Global Server Load Balancing CNAME (region-scoped):
        # `gtm-<region>-<hash>.gtm-i1d6.com`. This is the GTM/GSLB class of
        # products (F5 BIG-IP DNS / Citrix GTM and similar) — a DNS
        # load-balancer in front of the origin, NOT a WAF. Observed on
        # api-external.bank-example.co.id. The vendor behind a given
        # gtm-*.gtm-*.com zone is not named by the CNAME itself; classify as
        # the class, not the vendor, unless headers say otherwise.
        "cname": r"gtm-[a-z0-9-]+\.gtm-i1d6\.com|gtm-[a-z0-9-]+\.gtm-[a-z0-9]+\.(com|net)",
    },
]
