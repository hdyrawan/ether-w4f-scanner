"""Plain origin-server vendors (6).

Each entry is a vendor dict per the modular signature schema
(see _template.py). These are NOT WAF/CDN edges — they name the origin
stack so a bare host gets a verdict instead of "unknown". The low confidence
score (single header, 7%) reflects that.
"""

VENDORS = [
    {
        "name": "nginx",
        "headers": {"server": r"nginx(?:/|$)"},
    },
    {
        "name": "apache",
        "headers": {"server": r"apache(?:/|$)"},
    },
    {
        "name": "iis",
        # Plain Microsoft IIS origin — not a WAF/CDN, but naming it beats
        # "unknown" for mail/webmail/autodiscover hosts.
        "headers": {"server": r"microsoft-iis|microsoft-httpapi"},
    },
    {
        "name": "caddy",
        "headers": {"server": r"caddy"},
    },
    {
        "name": "litespeed",
        "headers": {"server": r"litespeed"},
    },
    {
        "name": "varnish",
        "headers": {"x-varnish": None, "via": r"varnish"},
        "cookies": [r"^cachewall"],
    },
]
