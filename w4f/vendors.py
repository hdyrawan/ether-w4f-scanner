"""Vendor signature assembly for w4f.

The signature *definitions* live in :mod:`w4f.signatures` — one file per
vendor (or a small logical group, see ``cdn.py``/``waf.py``/``bot.py``/
``gateways.py``/``origins.py``/``platforms.py``). This module is the engine
side: it loads every signature module through the validating loader and
exposes the assembled table the fingerprint loop consumes.

The assembled shape is the same dict the pre-modular table used:

    VENDORS[name] = rules            # name key stripped after validation

Add a vendor by adding a file under ``w4f/signatures/`` (copy
``_template.py``) — no changes here, in the matcher, CLI, or confidence
engine required.
"""

from __future__ import annotations

import ipaddress
import threading

from w4f.signatures import load_signatures, load_extra  # noqa: F401 (re-exported for tooling)

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

# Assembled from w4f/signatures/*.py at import time. A bad signature fails
# fast here with SignatureError instead of silently matching nothing.
VENDORS: dict[str, dict] = load_signatures()

# Optional extra local rules: W4F_SIGNATURES=/path/to/rules.py overrides or
# adds vendors by name (same VENDOR/VENDORS shape as the package modules).
import os as _os

_extra_path = _os.environ.get("W4F_SIGNATURES")
if _extra_path:
    VENDORS.update(load_extra(_extra_path))

_NET_CACHE: dict[str, list] = {}
_NET_LOCK = threading.Lock()


def vendor_nets(name: str) -> list:
    """Compile a vendor's netblock strings once, thread-safely."""
    with _NET_LOCK:
        if name not in _NET_CACHE:
            _NET_CACHE[name] = [ipaddress.ip_network(n) for n in VENDORS[name].get("nets", [])]
    return _NET_CACHE[name]
