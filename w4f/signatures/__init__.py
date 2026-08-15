"""Modular vendor signatures.

Each module under :mod:`w4f.signatures` (except private ``_*`` files) exports
either a single vendor dict or a list of them::

    VENDOR = {"name": "my-vendor", "headers": {...}, ...}
    VENDORS = [ {"name": "vendor-a", ...}, {"name": "vendor-b", ...} ]

The loader discovers every non-private module in this package, validates each
vendor (unique ``name``, known keys only, compilable regexes, valid
``requires``), and assembles the dict the fingerprint engine consumes:

    VENDORS[name] = {rules}        # 'name' key stripped after validation

Adding a vendor is a PR that adds ONE file under this package (copy
``_template.py``) — no changes to the matcher, CLI, or confidence engine.
"""

from __future__ import annotations

import importlib
import importlib.util
import ipaddress
import pkgutil
import re
import sys

# Keys a vendor rule may carry. Everything else is a hard error.
_ALLOWED_KEYS = {
    "name", "headers", "cookies", "cert", "cname", "ptr", "nets",
    "requires", "weights", "deployment", "block",
}
# Keys a `block` rule (the --verify / refusal-response block page) may carry.
# Block pages used to live in a hardcoded if-chain inside scanner.py, which
# meant adding one edited the matcher — breaking this package's promise that
# a vendor is ONE file. They are declared here instead, per vendor.
_BLOCK_KEYS = {
    "title",         # regex, matched against the lowercased <title>
    "body",          # list of markers, ALL must appear in the lowercased body
    "body_any",      # list of markers, ANY may appear
    "head",          # list of markers, ALL must appear in the lowercased head
    "priority",      # lower runs first; specific rules must beat generic ones
    "vendor",        # reported name when it differs from the signature name
    "interception",  # True = a box on the SCANNER's path, not the target's edge
    "deployment",    # which product variant this page identifies
}
# How the vendor sits in front of the origin. This decides which interception
# route can work at all — a cloud edge is reached by DNS delegation/anycast
# (SNI-based routing, the origin is elsewhere), an on-prem appliance sits on
# the origin's own address. Optional: vendors sold BOTH ways (Imperva
# Incapsula vs SecureSphere) must leave it unset and let the observed
# evidence say which, rather than assert a default that is wrong half the time.
_DEPLOYMENTS = {"cloud", "on-prem", "origin"}
# Keys the fingerprint engine actually reads (in addition to the allowed set).
_RULE_KEYS = _ALLOWED_KEYS - {"name"}
# Signal kinds a ``requires`` spec may reference (must mirror scanner.py).
_REQUIRE_KINDS = {"header", "cookie", "cert", "cname", "ptr", "netblock"}
# Confidence categories a ``weights`` override may set (must mirror scanner.py).
_WEIGHT_KINDS = {"netblock", "cert", "cname", "ptr", "headers", "cookies"}


class SignatureError(ValueError):
    """A signature module failed validation (bad name, key, or regex)."""


def _module_vendors(mod) -> list[dict]:
    """Pull VENDOR/VENDORS out of a signature module; empty is fine."""
    out = []
    single = getattr(mod, "VENDOR", None)
    many = getattr(mod, "VENDORS", None)
    if single is not None:
        if not isinstance(single, dict):
            raise SignatureError(f"{mod.__name__}: VENDOR must be a dict")
        out.append(single)
    if many is not None:
        if not isinstance(many, list):
            raise SignatureError(f"{mod.__name__}: VENDORS must be a list of dicts")
        out.extend(many)
    return out


def _validate_regex(kind: str, value) -> None:
    try:
        re.compile(value)
    except (re.error, TypeError) as e:
        raise SignatureError(f"bad regex in {kind}: {value!r} ({e})") from e


def _validate_requires(name: str, requires) -> None:
    if not isinstance(requires, list):
        raise SignatureError(f"{name}: 'requires' must be a list")
    for alt in requires:
        specs = alt if isinstance(alt, list) else [alt]
        for spec in specs:
            if not isinstance(spec, dict):
                raise SignatureError(f"{name}: requires entry must be a dict")
            kind = spec.get("kind")
            if kind not in _REQUIRE_KINDS:
                raise SignatureError(
                    f"{name}: requires kind {kind!r} not in {sorted(_REQUIRE_KINDS)}")
            if "re" in spec:
                _validate_regex(f"{name}.requires.{kind}", spec["re"])
            if kind == "netblock":
                for n in spec.get("nets", []):
                    try:
                        ipaddress.ip_network(n)
                    except ValueError as e:
                        raise SignatureError(f"{name}: bad netblock {n!r}: {e}") from e


def _validate_vendor(v: dict) -> None:
    name = v.get("name")
    if not name or not isinstance(name, str):
        raise SignatureError("vendor dict missing a string 'name'")
    unknown = set(v) - _ALLOWED_KEYS
    if unknown:
        raise SignatureError(f"{name}: unknown key(s) {sorted(unknown)} "
                             f"(allowed: {sorted(_ALLOWED_KEYS)})")
    for hk, hv in (v.get("headers") or {}).items():
        # None = presence; a string = regex
        if hv is not None:
            _validate_regex(f"{name}.headers.{hk}", hv)
    for i, c in enumerate(v.get("cookies") or []):
        _validate_regex(f"{name}.cookies[{i}]", c)
    for kind in ("cert", "cname", "ptr"):
        if kind in v and v[kind] is not None:
            _validate_regex(f"{name}.{kind}", v[kind])
    for i, n in enumerate(v.get("nets") or []):
        try:
            ipaddress.ip_network(n)
        except ValueError as e:
            raise SignatureError(f"{name}: bad netblock {n!r}: {e}") from e
    if "requires" in v:
        _validate_requires(name, v["requires"])
    for w in (v.get("weights") or {}):
        if w not in _WEIGHT_KINDS:
            raise SignatureError(
                f"{name}: weights category {w!r} not in {sorted(_WEIGHT_KINDS)}")
    if "deployment" in v and v["deployment"] not in _DEPLOYMENTS:
        raise SignatureError(
            f"{name}: deployment {v['deployment']!r} not in {sorted(_DEPLOYMENTS)}")
    _validate_block(name, v.get("block"))


def _validate_block(name: str, block) -> None:
    """A vendor may carry one block rule or a list of them (Imperva ships a
    cloud page AND an on-prem page; FortiWeb localizes its title)."""
    if block is None:
        return
    rules = block if isinstance(block, list) else [block]
    for rule in rules:
        if not isinstance(rule, dict):
            raise SignatureError(f"{name}: block rule must be a dict")
        unknown = set(rule) - _BLOCK_KEYS
        if unknown:
            raise SignatureError(f"{name}: unknown block key(s) {sorted(unknown)} "
                                 f"(allowed: {sorted(_BLOCK_KEYS)})")
        if "title" in rule:
            _validate_regex(f"{name}.block.title", rule["title"])
        for key in ("body", "body_any", "head"):
            if key in rule and not isinstance(rule[key], list):
                raise SignatureError(f"{name}: block.{key} must be a list of markers")
        if not any(k in rule for k in ("title", "body", "body_any", "head")):
            raise SignatureError(f"{name}: block rule matches nothing "
                                 f"(needs title/body/body_any/head)")
        if "deployment" in rule and rule["deployment"] not in _DEPLOYMENTS:
            raise SignatureError(
                f"{name}: block deployment {rule['deployment']!r} "
                f"not in {sorted(_DEPLOYMENTS)}")


def load_signatures(package: str = __name__) -> dict[str, dict]:
    """Discover, validate, and assemble every vendor in this package.

    Walks the package recursively — a vendor may live in any subpackage
    (``cdn/cloudflare.py``, ``waf/fortiweb.py``, …) or directly under
    ``w4f/signatures/``. Private modules (``_*``) are skipped.

    Returns ``{name: rules}`` where ``rules`` is the vendor dict with the
    ``name`` key stripped — the exact shape the fingerprint engine consumes.
    Raises :class:`SignatureError` on the first invalid vendor (duplicate
    name, unknown key, bad regex, invalid requires/weights/netblock).
    """
    pkg = importlib.import_module(package)
    merged: dict[str, dict] = {}
    for info in sorted(pkgutil.walk_packages(pkg.__path__, prefix=package + "."),
                       key=lambda m: m.name):
        if info.name.rsplit(".", 1)[-1].startswith("_"):
            continue  # private helpers / template are not signatures
        mod = importlib.import_module(info.name)
        for v in _module_vendors(mod):
            _validate_vendor(v)
            name = v["name"]
            if name in merged:
                raise SignatureError(f"duplicate vendor name: {name!r}")
            # strip 'name' so the assembled dict is byte-identical to the
            # pre-modular layout the fingerprint loop and tests consume
            merged[name] = {k: v[k] for k in _RULE_KEYS if k in v}
    return merged


def load_extra(path: str) -> dict[str, dict]:
    """Load extra vendor signatures from a Python file (W4F_SIGNATURES).

    Same validation as the package; names already in the builtin set are
    OVERRIDDEN (a local rule wins), new names are added. Kept deliberately
    small — one file, same VENDOR/VENDORS shape.
    """
    spec = importlib.util.spec_from_file_location("w4f_signatures_extra", path)
    if spec is None or spec.loader is None:
        raise SignatureError(f"cannot load signature file: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    out: dict[str, dict] = {}
    for v in _module_vendors(mod):
        _validate_vendor(v)
        name = v["name"]
        if name in out:
            raise SignatureError(f"duplicate vendor name in extra file: {name!r}")
        out[name] = {k: v[k] for k in _RULE_KEYS if k in v}
    return out


__all__ = ["SignatureError", "load_signatures", "load_extra"]
