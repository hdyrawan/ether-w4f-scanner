"""Platform / origin-edge vendors (6).

Each entry is a vendor dict per the modular signature schema
(see _template.py). These are managed hosting / platform edges (Squarespace,
Wix, ByteDance, AWS App Runner) plus the remaining edge classes.
"""

VENDORS = [
    {
        "name": "google-gfe",
        # Do NOT key on `alt-svc: h3` — HTTP/3 advertisement is web-wide
        # (Cloudflare, Fastly, nginx+quic all send it) and mislabels any
        # HTTP/3 host as GFE. The Server token and the 1e100.net PTR are
        # the Google-specific signals. The GTS issuer cert is NOT sufficient
        # on its own — Google Trust Services now issues certs for Cloudflare
        # and many other non-Google hosts, so a GTS cert alone would phantom
        # google-gfe everywhere.
        "headers": {"server": r"gws|gfe|esf"},
        "cert": r"google trust services",
        "ptr": r"1e100\.net|googleusercontent\.com",
        "requires": [
            {"kind": "header", "name": "server", "re": r"gws|gfe|esf"},
            {"kind": "ptr", "re": r"1e100\.net|googleusercontent\.com"},
        ],
    },
    {
        "name": "pepyaka",
        # Wix's own edge (Fastly-backed): server Pepyaka + x-cache-status.
        "headers": {"server": r"pepyaka", "x-cache-status": None},
        "cname": r"wix\.com|fastly",
    },
    {
        "name": "squarespace",
        # Squarespace managed platform edge: serves `server: Squarespace`
        # on every response (concrete header — exact match, no glob).
        "headers": {"server": r"squarespace"},
        "cname": r"squarespace\.com|squarespace\.",
    },
    {
        "name": "azure-app-service",
        # Azure App Service / App Gateway family: ARRAffinity cookie + azurewebsites.
        "cookies": [r"^ARRAffinity", r"^ARRAffinitySameSite"],
        "cname": r"azurewebsites\.net|azurefd\.net",
    },
    {
        "name": "bytedance",
        # ByteDance edge (TikTok/抖音 family): server TLB + x-tt-* headers.
        # akamaized is NOT a ByteDance CNAME — Akamai customers use it too,
        # so matching it here would false-positive every Akamai host as
        # bytedance. ByteDance-owned suffixes only.
        "headers": {"server": r"tlb", "x-tt-logid": None, "x-tt-trace-id": None,
                    "x-bytefaas-request-id": None},
        "cname": r"bytecdn|byteimg|byteacctimg|tikcdn|tiktokcdn",
    },
]
