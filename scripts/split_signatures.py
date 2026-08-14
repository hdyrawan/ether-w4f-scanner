"""One-time migration: split flat group modules into per-vendor files.

w4f/signatures/cdn.py (24 vendors)  -> w4f/signatures/cdn/<vendor>.py
w4f/signatures/waf.py (16 vendors)  -> w4f/signatures/waf/<vendor>.py
... and so on for bot/gateways/origins/platforms.

Each vendor file exports a single ``VENDOR`` dict. Values are copied from
the in-memory group modules, so the assembled table is byte-identical
(the existing test_signatures + a rule diff verify this).
"""

from __future__ import annotations

import os
import pprint
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

GROUPS = {
    "cdn": "w4f.signatures.cdn",
    "waf": "w4f.signatures.waf",
    "bot": "w4f.signatures.bot",
    "gateways": "w4f.signatures.gateways",
    "origins": "w4f.signatures.origins",
    "platforms": "w4f.signatures.platforms",
}

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "w4f", "signatures")


def main() -> None:
    for category, modname in GROUPS.items():
        mod = __import__(modname, fromlist=["VENDORS"])
        vend = getattr(mod, "VENDORS")
        cat_dir = os.path.join(BASE, category)
        os.makedirs(cat_dir, exist_ok=True)
        with open(os.path.join(cat_dir, "__init__.py"), "w") as f:
            f.write(f'"""Vendor signatures — {category} family (one file per vendor)."""\n')
        for v in vend:
            name = v["name"]
            body = pprint.pformat(v, width=100, sort_dicts=False)
            path = os.path.join(cat_dir, f"{name}.py")
            with open(path, "w") as f:
                f.write(f'"""{name} — {category} vendor signature. See _template.py for the schema."""\n\n')
                f.write(f"VENDOR = {body}\n")
            print(f"wrote {category}/{name}.py")


if __name__ == "__main__":
    main()
