"""TEMPLATE — copy this file to add a new vendor signature.

To add a vendor:
  1. Copy this file to ``w4f/signatures/<vendor>.py`` (or add to a logical
     group file like ``cdn.py`` / ``waf.py`` — see those files for examples).
  2. Set the ``name`` and fill in the signals you observed. Delete the
     fields you do not use — a field must not be present with an empty value.
  3. Run the tests:  ``python -m pytest tests/ -q``
  4. Add a small test for your vendor in ``tests/test_fingerprint.py``
     (search for ``test_squarespace_platform`` for the smallest example).
  5. Open a PR — no changes to the matcher, CLI, or confidence engine needed.

The loader (``w4f/signatures/__init__.py``) validates every module: unique
``name``, known keys only, compilable regexes, valid ``requires``/``weights``.
A bad signature fails fast with a ``SignatureError`` at import time.
"""

VENDOR = {
    # REQUIRED — unique across all signature modules. This is the name the
    # fingerprint engine reports in the verdict and the SARIF rule id
    # (w4f/<name>).
    "name": "my-vendor",

    # OPTIONAL — header signals. Key = header name (lowercase); the value is
    # a regex against the header VALUE, or None for "presence is enough".
    # A key ending in "*" is a PREFIX match against any header name
    # (e.g. "x-tyk-*" matches x-tyk-request-id). Matched exactly, so write
    # the real header name — a glob that never fires is a dead rule.
    "headers": {
        "server": r"my-vendor(?:/|$)",
        "x-my-vendor-id": None,
    },

    # OPTIONAL — cookie signals. Each entry is a regex against one
    # Set-Cookie value.
    "cookies": [
        r"^myvendor_session=",
    ],

    # OPTIONAL — regex against the leaf cert issuer+subject (lowercased).
    "cert": r"my vendor",

    # OPTIONAL — regex against any CNAME in the chain (lowercased).
    "cname": r"myvendor\\.com",

    # OPTIONAL — regex against any PTR of any resolved IP (lowercased).
    "ptr": r"myvendor\\.net",

    # OPTIONAL — IP networks the host must resolve inside of.
    "nets": [
        "203.0.113.0/24",
    ],

    # OPTIONAL — AND/OR gate for composite rules. The base matcher ORs all
    # signal kinds (any single header is enough to fire); `requires` demands
    # more. It is a list of alternatives (OR across); each alternative is
    # either a single spec or a list that must ALL match (AND within):
    "requires": [
        # alternative: header X AND cookie Y must both be present
        [{"kind": "header", "name": "server", "re": r"my-vendor"},
         {"kind": "cookie", "re": r"^myvendor_session="}],
        # alternative: a presence-only header is enough on its own
        {"kind": "header", "name": "x-my-vendor-id"},
    ],

    # OPTIONAL — confidence weights override for the six categories
    # (netblock/cert/cname/ptr/headers/cookies). Defaults are in
    # w4f/scanner.py CONF_WEIGHTS; only override when a signal is unusually
    # strong (e.g. an exclusive CNAME suffix) or unusually weak.
    "weights": {
        "cname": 25,
    },
}
