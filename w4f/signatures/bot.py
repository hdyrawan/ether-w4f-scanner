"""Bot-management vendors (5).

Each entry is a vendor dict per the modular signature schema
(see _template.py). Bot-management edges sit in front of or alongside classic
WAFs and emit challenge cookies / headers of their own.
"""

VENDORS = [
    {
        "name": "datadome",
        # Bot-management JS challenge: datadome cookie + x-datadome header.
        "headers": {"x-datadome": None, "server": r"datadome"},
        "cookies": [r"^datadome="],
    },
    {
        "name": "perimeterx",
        # HUMAN / PerimeterX bot management: _px* cookies.
        "headers": {"x-px-*": None, "server": r"perimeterx"},
        "cookies": [r"^_px\d*=", r"^_pxhd=", r"^_px3="],
    },
    {
        "name": "kasada",
        # Kasada bot defense: kpsdk* cookies + x-kpsdk-ct header.
        "headers": {"x-kpsdk-ct": None, "x-kasada-*": None},
        "cookies": [r"^kpsdk_ct=", r"^kpsdk=", r"^kpsdkutm="],
    },
    {
        "name": "shape-security",
        # Shape Security (F5) bot defense: shape_* cookies + x-shape header.
        "headers": {"x-shape-*": None, "server": r"shape"},
        "cookies": [r"^shape_", r"^__shape"],
    },
    {
        "name": "arkose",
        # Arkose Labs (now part of Fortinet) bot/liveness: arkose* cookies.
        "cookies": [r"^arkose", r"^_arkose"],
    },
]
