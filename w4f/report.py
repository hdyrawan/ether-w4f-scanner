"""Output formatting: per-host console blocks and a doc-ready markdown sweep.

Console output is deliberately plain: aligned `label   value` lines, no
markdown bold/bullets, color only for the verdict. The markdown sweep
(--md) is separate and keeps full markdown for embedding in docs.
"""

from __future__ import annotations

import re

from w4f import attribution as ATT
from w4f.attribution import attribute
from w4f.vendors import INTERESTING_HEADERS

# ANSI
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_MAGENTA = "\033[35m"
_BLUE = "\033[34m"
_BRIGHT_YELLOW = "\033[93m"
_BRIGHT_CYAN = "\033[96m"
_BRIGHT_BLUE = "\033[94m"
_BRIGHT_MAGENTA = "\033[95m"
_BRIGHT_RED = "\033[91m"
_BOLD = "\033[1m"
_CRIT = "\033[1;91m"  # bold bright red — aggressive for mTLS/block/error flags
_DIM = "\033[2m"
_RESET = "\033[0m"

# Per-vendor verdict colors so a glance names the edge. Exact name wins,
# then a family prefix (aws-*, azure-*, tencent-*), then the default.
VENDOR_COLORS: dict[str, str] = {
    "cloudflare": _BRIGHT_YELLOW,          # brand orange ≈ bright yellow
    "cloudflare-waf": _BRIGHT_YELLOW,
    "akamai": _BLUE,
    "fastly": _RED,
    "fastly-waf": _RED,
    "imperva": _YELLOW,
    "aws-cloudfront": _CYAN,
    "aws-waf": _CYAN,
    "azure-frontdoor": _BRIGHT_BLUE,
    "google-gfe": _MAGENTA,
    "gcp-armor": _MAGENTA,
    "f5": _BRIGHT_RED,
    "netscaler": _BRIGHT_RED,
    "fortiweb": _BRIGHT_YELLOW,
    "sucuri": _GREEN,
    "kong": _BRIGHT_CYAN,
    "wso2": _BRIGHT_RED,
    "vercel": _BRIGHT_MAGENTA,
    "squarespace": _BRIGHT_MAGENTA,
    "aliyun": _RED,
    "wangsu": _BRIGHT_BLUE,
    "chinacache": _CYAN,
    "jiasule": _BRIGHT_YELLOW,
    "wswaf": _YELLOW,
    "knownsec": _BRIGHT_CYAN,
    "volcengine": _BRIGHT_MAGENTA,
    "baidu-bfe": _BLUE,
    "baishan": _GREEN,
    "netease": _GREEN,
    "360panyun": _BRIGHT_YELLOW,
    "qiniu": _GREEN,
    "huawei-cloud-cdn": _BRIGHT_BLUE,
    "baidu-cdn": _BLUE,
    "qrator": _YELLOW,
    "360wangzhanbao": _BRIGHT_YELLOW,
    "variti": _YELLOW,
    "uewaf": _BRIGHT_CYAN,
    "airee": _GREEN,
    "jd-cloud": _GREEN,
    "azion": _CYAN,
    "wordpress-vip": _BRIGHT_MAGENTA,
}
_VENDOR_PREFIX_COLORS: list[tuple[str, str]] = [
    ("aws-", _CYAN), ("azure-", _BRIGHT_BLUE), ("tencent-", _BRIGHT_MAGENTA),
]
# Plain origin stacks are DIM (they are the origin, not the edge).
_ORIGIN_VENDORS = {
    "nginx", "apache", "iis", "caddy", "litespeed", "varnish",
    "envoy", "haproxy", "tengine", "openresty", "sgw",
}

_LABEL = 10  # column width for the left-hand label


def _color_enabled() -> bool:
    """Colors when stdout is a TTY and NO_COLOR is not set."""
    import os
    import sys
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _wrap(text: str, code: str) -> str:
    """Wrap text in color+reset, or return it plain when colors are off."""
    if not _color_enabled():
        return text
    return f"{code}{text}{_RESET}"


def _vendor_color(vendor: str) -> str:
    if not _color_enabled():
        return ""
    if vendor in VENDOR_COLORS:
        return VENDOR_COLORS[vendor]
    if vendor in _ORIGIN_VENDORS:
        return _DIM
    for prefix, color in _VENDOR_PREFIX_COLORS:
        if vendor.startswith(prefix):
            return color
    return _GREEN


def _row(label: str, value: str) -> str:
    return f"{label:<{_LABEL}}{value}"


def _row2(label: str, value: str) -> str:
    """Indented label/value row for the triage block — the 2-space indent plus
    an 8-wide label keeps values in the same column as :func:`_row`."""
    return f"  {label:<8}{value}"


# Signal-category abbreviations for the "basis" cell. WHAT a verdict rests on
# is more actionable than the percentage those categories sum to: "net+cert"
# is ownership evidence, "hdr" alone is a string anyone can set.
_CAT_ABBR = {
    "netblock": "net", "cert": "cert", "cname": "cname",
    "ptr": "ptr", "headers": "hdr", "cookies": "cookie",
}
# Categories the origin cannot fake by echoing a header.
_HARD_CATS = {"netblock", "cert", "cname", "ptr"}


def _basis(m: dict) -> str:
    """``"net+cert+hdr"`` — the signal categories behind one verdict.

    Result trees written before 0.1.32 carry no ``categories`` key; those
    render as ``-`` instead of raising (``--json`` files are re-read by the
    sweep harness).
    """
    cats = m.get("categories") or []
    return "+".join(_CAT_ABBR.get(c, c) for c in cats) or "-"


def _is_weak(m: dict) -> bool:
    """True when a verdict rests ONLY on headers/cookies (spoofable)."""
    cats = set(m.get("categories") or [])
    return bool(cats) and not (cats & _HARD_CATS)


def _attribution(r: dict) -> dict:
    """The result's attribution, computed on demand for older result trees.

    ``probe_one`` stores it, but ``--json`` files written before the model
    existed (and hand-built test fixtures) do not carry one — deriving it
    here keeps every renderer working on both.
    """
    att = r.get("attribution")
    return att if att else attribute(r)


# Confidence bands are what a reader acts on; the number is the tiebreak.
_BAND_SHORT = {ATT.HIGH: "HIGH", ATT.MEDIUM: "MED", ATT.LOW: "LOW"}
_BAND_COLOR = {ATT.HIGH: _GREEN, ATT.MEDIUM: _YELLOW, ATT.LOW: _DIM}


def _conf_cell(att: dict) -> str:
    """``HIGH 92`` — band first, because that is the decision."""
    if att.get("state") == ATT.STATE_AMBIGUOUS:
        cands = att.get("candidates") or []
        if cands:
            band = _BAND_SHORT.get(cands[0].get("confidence"), "?")
            return f"{band} {cands[0].get('score', 0)}"
        return "-"
    if att.get("score") is None:
        return "-"
    return f"{_BAND_SHORT.get(att.get('confidence'), '?')} {att['score']}"


def _basis_pretty(basis) -> str:
    """``net + cname + hdr`` — spaced for the per-host block."""
    return " + ".join(_CAT_ABBR.get(c, c) for c in (basis or [])) or "-"


def _candidate_line(cand: dict, indent: str = "  ", width: int = 30) -> str:
    """``  cloudflare                     HIGH  92`` — one candidate, aligned."""
    vendor = cand.get("vendor", "?")
    color = _vendor_color(vendor)
    name = _wrap(vendor, _BOLD + color) if color else _wrap(vendor, _BOLD)
    pad = " " * max(1, width - len(vendor))
    band = cand.get("confidence") or "?"
    band_txt = _wrap(f"{band:<6}", _BAND_COLOR.get(band, ""))
    return f"{indent}{name}{pad}{band_txt}{cand.get('score', 0):>3}"


def fmt_verdict(verdict: list[dict]) -> str:
    if not verdict:
        return "unknown-edge (no signature matched)"
    return ", ".join(
        f"{m['vendor']}({m.get('confidence', 0)}%, {_basis(m)})" for m in verdict
    )


def fmt_block(r: dict) -> str:
    att = _attribution(r)
    if r.get("error") and not (r.get("verdict") or (r.get("tls") or {}).get("cert")):
        return f"{r['hostport']}\n{_row('error', _wrap(r['error'], _RED))}"

    res = r.get("resolved") or {}
    tls = r.get("tls") or {}
    cert = tls.get("cert") or {}

    lines = [
        _wrap(r["hostport"], _CYAN),
        _row("ip", ", ".join(res.get("ips", ["-"]))),
    ]
    if res.get("ptr"):
        lines.append(_row("ptr", ", ".join(res["ptr"][:3])))
    if res.get("cname"):
        lines.append(_row("cname", ", ".join(res["cname"][:5])))
    lines.append(
        _row(
            "tls",
            f"{tls.get('tls_version') or '-'}  {tls.get('cipher') or '-'}"
            f"  ALPN {tls.get('alpn') or '-'}",
        )
    )
    if r.get("http2_negotiated"):
        lines.append(_row("  http2", _wrap("negotiated h2; GET used HTTP/1.1 (header view is the 1.1 view)", _YELLOW)))
    if tls.get("mtls"):
        lines.append(_row("mtls", _wrap("server wants a CLIENT certificate", _RED)))
    if cert.get("subject"):
        issuer = f"{cert.get('issuer_org') or cert.get('issuer')}"
        # chain trust is evidence too — the scanner records it but the
        # console never showed it (only --json did).
        cv = r.get("chain_verified")
        if cv is True:
            issuer += _wrap("  (chain verified)", _DIM)
        elif cv is False:
            issuer += _wrap("  (chain NOT verified)", _YELLOW)
        lines.append(_row("cert", issuer))
        # a wildcard cert can carry 50+ SANs — that one line used to bury the
        # whole block; the full list stays in --json
        lines.append(_row("  san", _san_summary(cert, limit=6) or "-"))
    if cert.get("days_remaining") is not None:
        lines.append(
            _row(
                "  valid",
                f"{cert.get('not_before','')[:10]} -> {cert.get('not_after','')[:10]}"
                f"  ({cert.get('days_remaining')}d left)",
            )
        )
    if cert.get("spki_sha256"):
        lines.append(_row("  spki", cert.get("spki_sha256")))
    if r.get("ws"):
        ws = r["ws"]
        if ws.get("upgrade_supported"):
            lines.append(_row("ws", _wrap(f"101 Switching Protocols (accept: {ws.get('sec_websocket_accept') or '-'})", _GREEN)))
        elif ws.get("status"):
            lines.append(_row("ws", f"upgrade {ws['status']}"))
        elif ws.get("error"):
            lines.append(_row("ws", _wrap(ws["error"], _DIM)))
    if r.get("grpc"):
        g = r["grpc"]
        if g.get("grpc_supported"):
            msg = f"supported (grpc-status {g.get('grpc_status', '?')})"
            if g.get("grpc_message"):
                msg += f"  {g['grpc_message']}"
            lines.append(_row("grpc", _wrap(msg, _GREEN)))
        elif g.get("status"):
            lines.append(_row("grpc", f"rejected {g['status']}"))
        elif g.get("error"):
            lines.append(_row("grpc", _wrap(g["error"], _DIM)))
    if cert.get("key_type"):
        lines.append(
            _row("  key", f"{cert.get('key_type')} {cert.get('key_size','')}  {cert.get('signature')}")
        )

    http = tls.get("http")
    if http:
        status = http.get("status", "-")
        # truncate long error tails like "( _ssl.c:2578)" — the useful part is
        # the alert name, not the C source location.
        if status.startswith("ERROR:"):
            status = re.sub(r"\s*\(_ssl\.c:\d+\)$", "", status)
        lines.append(_row("http", status[:90]))
        # The redirect chain decides WHICH host the headers above describe:
        # the apex is often a bare redirector and the WAF only sits on www.
        # Recorded since 0.1.10, shown nowhere until 0.1.32.
        if http.get("redirects"):
            hops = http["redirects"]
            chain = " -> ".join(h[:60] for h in hops[:3])
            if len(hops) > 3:
                chain += f" -> (+{len(hops) - 3} more)"
            lines.append(_row("  chain", _wrap(chain, _YELLOW)))
            lines.append(_row("  final", f"{http.get('final_host') or '-'}"
                                         f"  (headers above are from here)"))
        interesting = []
        for h, v in (http.get("headers") or {}).items():
            if any(re.match(hp, h) for hp in INTERESTING_HEADERS):
                interesting.append(f"{h}={v[:70]}")
        if interesting:
            # vendor-ish headers first: the list is capped at 8, and generic
            # security headers (HSTS/CSP/X-Frame-Options) used to push the
            # actual fingerprint (server, via, x-cache) off the end
            interesting.sort(key=lambda hv: hv.split("=", 1)[0].lower() in _LEAD_NOISE)
            # one header per line so long cookies/server strings don't wrap ugly
            for hdr in interesting[:8]:
                lines.append(_row("  hdr", hdr))

    lines.extend(_analysis_sections(att, r))

    blk = r.get("block")
    if blk:
        how = ("block page returned to the NORMAL request"
               if blk.get("source") == "passive" else "provoked by --verify")
        # the page can name the product variant even when the vendor's own
        # signature cannot (Imperva cloud vs on-prem)
        dep = f" ({blk['deployment']})" if blk.get("deployment") else ""
        lines.append(
            _row("block", _wrap(
                f"{blk['vendor']}{dep} — {blk['title']} ({blk.get('status','')})"
                f" [{blk.get('confidence', 95)}% conf]",
                _YELLOW))
        )
        lines.append(_row("     ", _wrap(how, _DIM)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Triage view (default): summary table + per-host blocks + sweep rollup.
# ---------------------------------------------------------------------------


def _term_width() -> int | None:
    """Terminal width for adaptive columns, or None when output is piped.

    Piped output NEVER drops columns — a redirected sweep must be complete
    and identical regardless of the terminal that happened to produce it.
    """
    import shutil
    import sys
    try:
        if not sys.stdout.isatty():
            return None
    except Exception:
        return None
    return shutil.get_terminal_size((100, 24)).columns


def _pad(colored: str, plain: str, width: int, align: str = "<") -> str:
    """Pad a possibly-colored cell to `width` using its PLAIN length.

    Padding inside the ANSI escape would make str.ljust count the escape
    bytes and break every column to the right.
    """
    fill = " " * max(0, width - len(plain))
    return colored + fill if align == "<" else fill + colored


def _flag_tokens(r: dict) -> list[tuple[str, str]]:
    """(text, color) for each critical flag — one source of truth for the
    table's NOTES column and the per-host block header."""
    tls = r.get("tls") or {}
    http = tls.get("http") or {}
    out: list[tuple[str, str]] = []
    if tls.get("mtls"):
        out.append(("mTLS", _CRIT))
    if r.get("block"):
        blk = r["block"]
        tag = f"BLOCK {blk.get('vendor', '')}".rstrip()
        # a page handed to a NORMAL request is a different fact from one an
        # active probe provoked — never let the two blur
        if blk.get("source") == "passive":
            tag += "!"
        out.append((tag, _CRIT))
    if r.get("error"):
        out.append((f"ERR {r['error']}".rstrip(), _CRIT))
    if r.get("interception"):
        out.append(("INTERCEPTED", _CRIT))
    if http.get("redirects"):
        final = (http.get("final_host") or "").strip()
        out.append((f"->{final}" if final else "->redirect", _YELLOW))
    return out


def _flags(r: dict) -> list[str]:
    """Critical flags: mTLS / BLOCK / ERR / redirect, styled aggressively."""
    return [_wrap(t, c) for t, c in _flag_tokens(r)]


def _status_code(r: dict) -> str:
    """Bare HTTP status code for the table ("200"/"403"/"ERR"/"-")."""
    status = ((r.get("tls") or {}).get("http") or {}).get("status") or ""
    if not status:
        return "-"
    if status.startswith("ERROR"):
        return "ERR"
    m = re.search(r"\s(\d{3})(\s|$)", status)
    return m.group(1) if m else "-"


def _tls_cell(r: dict) -> str:
    tls = r.get("tls") or {}
    ver = (tls.get("tls_version") or "").replace("TLSv", "")
    if not ver:
        return "-"
    return f"{ver} {tls.get('alpn') or ''}".strip()


def _san_summary(cert: dict, limit: int) -> str:
    """First `limit` SAN entries + a "+N more" tail; "" when the cert has none.

    A wildcard cert can carry 50+ SANs, which is why both views cap it — the
    triage block tighter than --verbose.
    """
    sans = [s.strip() for s in str(cert.get("san") or "").split(",") if s.strip()]
    if not sans:
        return ""
    out = ", ".join(sans[:limit])
    if len(sans) > limit:
        out += f"  (+{len(sans) - limit} more)"
    return out


def _cert_cell(r: dict) -> str:
    """Issuer org + days remaining — cert identity is fingerprint evidence
    and an expiry cliff is worth seeing in a sweep."""
    cert = (r.get("tls") or {}).get("cert") or r.get("cert") or {}
    org = str(cert.get("issuer_org") or cert.get("issuer") or "").strip()
    org = org.split(",")[0]
    # mark the cut so a clipped CA name reads as clipped, not as a CA called
    # "Sectigo Limite"; the block below prints the full issuer
    if len(org) > 14:
        org = org[:13] + "…"
    days = cert.get("days_remaining")
    if days is None:
        return org or "-"
    return f"{org} {days}d".strip()


# Columns dropped (right to left) when the terminal is too narrow. CERT goes
# first because the block below repeats it; BASIS survives longest because it
# is the column that says whether a verdict can be trusted.
_TABLE_DROP_ORDER = ["cert", "http", "tls", "basis"]
_TABLE_COLS = [
    ("HOST", "host", "<"), ("EDGE", "edge", "<"), ("CONF", "conf", ">"),
    ("BASIS", "basis", "<"), ("TLS", "tls", "<"), ("CERT", "cert", "<"),
    ("HTTP", "http", ">"), ("NOTES", "notes", "<"),
]


def fmt_summary_table(results: list[dict]) -> str:
    """All-hosts table: HOST | EDGE | CONF | BASIS | TLS | CERT | HTTP | NOTES.

    Plain aligned text (no markdown); the edge is colored per-vendor and
    critical flags are bold red so a 20-50 host run scans in one glance.
    BASIS names the signal categories the verdict rests on (net/cert/cname/
    ptr/hdr/cookie) — "net+cert" is ownership evidence, a bare "hdr" is a
    string the origin can set, and that difference matters more than the
    percentage. Columns drop right-to-left on a narrow TTY; piped output
    always carries the full set.
    """
    if not results:
        return ""
    plain: list[dict[str, str]] = []
    for r in results:
        ver = r.get("verdict") or []
        top = ver[0] if ver else {}
        att = _attribution(r)
        state = att.get("state")
        # The EDGE cell reports the STATE, not just a name: an ambiguous pair
        # collapsed to its higher-scoring half reads as a confident answer,
        # and an intercepted host's "edge" may not be the target's at all.
        if state == ATT.STATE_AMBIGUOUS:
            edge = "AMBIGUOUS"
        elif state == ATT.STATE_INTERCEPTED:
            edge = "INTERCEPTED"
        elif state == ATT.STATE_ERROR:
            edge = "-"
        elif ver:
            edge = top.get("vendor", "unknown")
            if len(ver) > 1:
                edge += f" +{len(ver) - 1}"
        else:
            edge = "unknown"
        notes = " ".join(t for t, _ in _flag_tokens(r))
        if len(notes) > 44:
            notes = notes[:41] + "..."
        plain.append({
            "host": r["hostport"],
            "edge": edge,
            "conf": _conf_cell(att),
            "basis": _basis(top) if (ver and state != ATT.STATE_INTERCEPTED) else "-",
            "tls": _tls_cell(r),
            "cert": _cert_cell(r),
            "http": _status_code(r),
            "notes": notes,
        })

    widths = {key: max(len(head), max(len(p[key]) for p in plain))
              for head, key, _ in _TABLE_COLS}
    dropped: set[str] = set()
    term = _term_width()
    if term:
        def total() -> int:
            keys = [k for _, k, _ in _TABLE_COLS if k not in dropped]
            return sum(widths[k] for k in keys) + 2 * (len(keys) - 1)
        for key in _TABLE_DROP_ORDER:
            if total() <= term:
                break
            dropped.add(key)

    kept = [c for c in _TABLE_COLS if c[1] not in dropped]
    rows = ["  ".join(_pad(h, h, widths[k], a) for h, k, a in kept).rstrip()]
    for r, cells in zip(results, plain):
        ver = r.get("verdict") or []
        out = []
        for _, key, align in kept:
            val = cells[key]
            if key == "host":
                cell = _wrap(val, _CYAN)
            elif key == "edge":
                cell = _wrap(val, _BOLD + _vendor_color(ver[0]["vendor"])) if ver \
                    else _wrap(val, _DIM)
            elif key == "basis":
                cell = _wrap(val, _DIM if not (ver and _is_weak(ver[0])) else _YELLOW)
            elif key == "notes":
                cell = "  ".join(_wrap(t, c) for t, c in _flag_tokens(r))
                if len(val) > 44:  # was truncated for width math
                    cell = _wrap(val, _CRIT)
            else:
                cell = val
            out.append(_pad(cell, val, widths[key], align))
        rows.append("  ".join(out).rstrip())
    return "\n".join(rows)


# Response headers that say nothing about the edge — excluded from the
# "leads" line so an unknown verdict shows only fingerprintable material.
_LEAD_NOISE = {
    "strict-transport-security", "x-frame-options", "content-security-policy",
    "x-content-type-options", "x-xss-protection", "referrer-policy",
    "x-download-options", "x-permitted-cross-domain-policies",
    "x-ua-compatible", "x-dns-prefetch-control",
}
# Headers whose VALUE is the fingerprint ("server: acme-edge"), so it is kept
# however long; everything else keeps the value only when it is short.
_LEAD_VALUE_HEADERS = {"server", "via", "x-powered-by", "x-cdn", "x-cache",
                       "x-served-by"}


def _unmatched_leads(r: dict, limit: int = 4) -> str:
    """Fingerprintable headers/cookies present on an UNKNOWN edge.

    AGENTS.md trap #7: an unknown verdict is a tool gap to fix, not a result
    to accept. Printing the vendor-ish headers that matched nothing turns
    every unknown host in a sweep into the lead for the next signature file.
    """
    http = (r.get("tls") or {}).get("http") or {}
    leads: list[str] = []
    for h, v in (http.get("headers") or {}).items():
        hl = h.lower()
        if hl in _LEAD_NOISE:
            continue
        if hl in ("server", "via", "x-powered-by") or hl.startswith("x-"):
            # A per-request id (x-…-request-id: 2C13:3DAD0C:…) is noise — its
            # NAME is the signal a rule would match on. Keep short values,
            # which is what distinguishes a POP/region marker.
            if v and (hl in _LEAD_VALUE_HEADERS or len(v) <= 16):
                leads.append(f"{h}: {v}")
            else:
                leads.append(h)
    for c in (http.get("set-cookie-list") or [])[:2]:
        leads.append(f"cookie {c.split('=', 1)[0]}")
    if not leads:
        return ""
    shown = " · ".join(leads[:limit])
    if len(leads) > limit:
        shown += f" · +{len(leads) - limit} more"
    return shown


def _evidence_summary(m: dict, limit: int = 3) -> str:
    ev = m.get("evidence") or []
    shown = " · ".join(e[:56] for e in ev[:limit])
    if len(ev) > limit:
        shown += f" · +{len(ev) - limit} more"
    return shown


def _observed_rows(r: dict, indent: str = "    ") -> list[str]:
    """OBSERVED — the facts the scan collected, with no vendor claim."""
    rows = []
    for label, value in ATT.observations(r):
        rows.append(f"{indent}{label:<10}{value}")
    return rows


def fmt_compact_block(r: dict) -> str:
    """Per-host block, driven by the attribution STATE.

    Each state answers a different question, so each gets its own shape: a
    named edge with its basis, a pair of candidates too close to separate,
    the raw observations behind an unknown, or the warning that the identity
    on the wire belongs to a box on our own path. Full evidence and response
    detail stay behind --verbose (fmt_block).
    """
    att = _attribution(r)
    state = att.get("state")
    head = _wrap(r["hostport"], _CYAN)
    flags = _flags(r)
    if flags:
        head += "  " + "  ".join(flags)
    lines = [head]

    if state == ATT.STATE_INTERCEPTED:
        icept = att.get("interception") or {}
        lines.append(_row2("EDGE", _wrap("NOT DETERMINED", _DIM)))
        lines.append(_row2("PATH", _wrap(
            f"INTERCEPTED by {icept.get('by', '?')}", _CRIT)))
        lines.append(_row2("", _wrap(
            "the identity below may belong to the interception device, "
            "not this host", _YELLOW)))
        lines.append("  OBSERVED")
        lines.extend(_observed_rows(r))
        return "\n".join(lines)

    if state == ATT.STATE_ERROR:
        lines.append(_row2("error", _wrap(str(att.get("error", ""))[:100], _CRIT)))
        return "\n".join(lines)

    if state == ATT.STATE_UNKNOWN:
        lines.append(_row2("EDGE", _wrap("UNKNOWN", _DIM)))
        obs = _observed_rows(r)
        if obs:
            lines.append("  OBSERVED")
            lines.extend(obs)
        leads = _unmatched_leads(r)
        if leads:
            # the fingerprintable headers that matched NO signature: an
            # unknown is a tool gap, and this is where the next rule starts
            lines.append(_row2("leads", _wrap(leads, _YELLOW)))
        return "\n".join(lines)

    if state == ATT.STATE_AMBIGUOUS:
        cands = att.get("candidates") or []
        lines.append(_row2("EDGE", _wrap("AMBIGUOUS", _YELLOW)))
        for cand in cands:
            lines.append(_candidate_line(cand, indent="    "))
        lines.append("  BASIS")
        for cand in cands:
            lines.append(f"    {cand.get('vendor', '?'):<20}"
                         f"{_wrap(_basis_pretty(cand.get('basis')), _DIM)}")
        lines.extend(_context_rows(r))
        return "\n".join(lines)

    # ATTRIBUTED
    lines.append(_candidate_line({"vendor": att.get("vendor", "?"),
                                  "confidence": att.get("confidence"),
                                  "score": att.get("score", 0)}, indent="  "))
    basis = _basis_pretty(att.get("basis"))
    if att.get("deployment"):
        basis += f"   ({att['deployment']})"
    suffix = ""
    if att.get("basis") and not (set(att["basis"]) & _HARD_CATS):
        suffix = _wrap("   (headers only — spoofable)", _YELLOW)
    lines.append("  " + _wrap(basis, _DIM) + suffix)
    for alt in att.get("alternatives") or []:
        role = f"  ({alt['role']})" if alt.get("role") == "origin" else ""
        lines.append(_wrap(f"    {alt.get('vendor', '?')}  {alt.get('score', 0)}{role}",
                           _DIM))
    if att.get("error"):
        # evidence survived a failed probe — show both, not one or the other
        lines.append(_row2("error", _wrap(str(att["error"])[:80], _CRIT)))
    lines.extend(_context_rows(r))
    return "\n".join(lines)


def _context_rows(r: dict) -> list[str]:
    """The response facts a decision needs next to the attribution."""
    tls = r.get("tls") or {}
    http = tls.get("http") or {}
    cert = tls.get("cert") or {}
    lines = []
    chain_bits = []
    if http.get("redirects"):
        hops = len(http["redirects"])
        chain_bits.append(f"-> {http.get('final_host') or '?'} ({hops} hop"
                          f"{'s' if hops > 1 else ''})")
    status = _status_code(r)
    if status != "-":
        chain_bits.append(status)
    if _tls_cell(r) != "-":
        chain_bits.append(f"TLS{_tls_cell(r)}")
    if chain_bits:
        lines.append(_row2("path", " · ".join(chain_bits)))
    cert_bits = []
    issuer = str(cert.get("issuer_org") or cert.get("issuer") or "").split(",")[0]
    if issuer:
        cert_bits.append(issuer)
    if cert.get("days_remaining") is not None:
        cert_bits.append(f"{cert['days_remaining']}d left")
    cv = r.get("chain_verified")
    if cv is True:
        cert_bits.append("chain verified")
    elif cv is False:
        cert_bits.append("chain NOT verified")
    if cert_bits:
        lines.append(_row2("cert", " · ".join(cert_bits)))
    san_line = _san_summary(cert, limit=3)
    if san_line:
        lines.append(_row2("san", san_line))
    icept = r.get("interception")
    if icept:
        lines.append(_row2("!", _wrap(
            f"TLS intercepted by {icept.get('by', '?')} between w4f and the "
            f"target ({icept.get('evidence', '')}) — cert and pin are the "
            f"middlebox's, NOT this host's", _CRIT)))
    if cert.get("spki_sha256"):
        lines.append(_row2("pin", _wrap(f"spki {cert['spki_sha256'][:16]}…", _DIM)))
    return lines


def _analysis_sections(att: dict, r: dict) -> list[str]:
    """--verbose: WHY the attribution was reached.

    EDGE names the call, EVIDENCE lists the observations behind it grouped
    by category, ALTERNATIVES shows what else was in play. Scores are shown
    as one number per candidate — never as the arithmetic that produced it.
    """
    state = att.get("state")
    out: list[str] = [""]

    if state == ATT.STATE_INTERCEPTED:
        icept = att.get("interception") or {}
        out.append("EDGE")
        out.append(_row2("", _wrap("NOT DETERMINED", _DIM)))
        out.append("PATH")
        out.append(_row2("", _wrap(f"INTERCEPTED by {icept.get('by', '?')}", _CRIT)))
        out.append(_row2("", _wrap(str(icept.get("evidence", "")), _DIM)))
        out.append(_row2("", _wrap(
            "the identity above may belong to the interception device", _YELLOW)))
        return out

    if state == ATT.STATE_UNKNOWN:
        out.append("EDGE")
        out.append(_row2("", _wrap("UNKNOWN — no signature matched", _DIM)))
        leads = _unmatched_leads(r, limit=8)
        if leads:
            out.append("LEADS")
            out.append(_row2("", _wrap(leads, _YELLOW)))
        return out

    if state == ATT.STATE_ERROR:
        out.append("EDGE")
        out.append(_row2("", _wrap(f"ERROR — {att.get('error', '')}", _CRIT)))
        return out

    if state == ATT.STATE_AMBIGUOUS:
        out.append("EDGE")
        out.append(_row2("", _wrap("AMBIGUOUS — candidates too close to separate",
                                   _YELLOW)))
        for cand in att.get("candidates") or []:
            out.append(_candidate_line(cand, indent="  "))
            out.append("  " + _wrap(f"  {_basis_pretty(cand.get('basis'))}", _DIM))
            out.append("  EVIDENCE")
            for ev in cand.get("evidence") or []:
                out.append(f"    {ev.get('label', ''):<14}{ev.get('detail', '')[:80]}")
        return out

    # ATTRIBUTED
    out.append("EDGE")
    out.append(_candidate_line({"vendor": att.get("vendor", "?"),
                                "confidence": att.get("confidence"),
                                "score": att.get("score", 0)}, indent="  "))
    detail = _basis_pretty(att.get("basis"))
    if att.get("deployment"):
        detail += f"   ({att['deployment']})"
    out.append("  " + _wrap(f"  {detail}", _DIM))
    if att.get("error"):
        out.append(_row2("", _wrap(f"probe error: {att['error']}", _CRIT)))
    evidence = att.get("evidence") or []
    if evidence:
        out.append("")
        out.append("EVIDENCE")
        for ev in evidence:
            label = ev.get("label") or ""
            out.append(f"  {label:<14}{ev.get('detail', '')[:90]}")
    alts = att.get("alternatives") or []
    if alts:
        out.append("")
        out.append("ALTERNATIVES")
        for alt in alts:
            role = f"   ({alt['role']})" if alt.get("role") == "origin" else ""
            out.append(_candidate_line(alt, indent="  ") + _wrap(role, _DIM))
            out.append("  " + _wrap(f"  {_basis_pretty(alt.get('basis'))}", _DIM))
    return out


def fmt_rollup(results: list[dict], elapsed: float | None = None) -> str:
    """Sweep rollup: vendor counts, unknowns, flags, weak verdicts.

    For a continuous sweep the aggregate IS the product — 87 rows scroll
    past, this is the part worth reading. Unknown hosts are named (up to a
    few) because they are the signature-mining queue.
    """
    if not results:
        return ""
    counts: dict[str, int] = {}
    unknown: list[str] = []
    weak = 0
    mtls = blocks = errors = 0
    for r in results:
        ver = r.get("verdict") or []
        if ver:
            counts[ver[0]["vendor"]] = counts.get(ver[0]["vendor"], 0) + 1
            if _is_weak(ver[0]):
                weak += 1
        elif not r.get("error"):
            unknown.append(r["hostport"])
        if (r.get("tls") or {}).get("mtls"):
            mtls += 1
        if r.get("block"):
            blocks += 1
        if r.get("error"):
            errors += 1

    width = min(_term_width() or 72, 72)
    head = f"{len(results)} hosts"
    if elapsed is not None:
        head += f" · {elapsed:.1f}s"
    lines = [_wrap("── " + head + " " + "─" * max(0, width - len(head) - 4), _DIM)]

    if counts:
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        shown = " · ".join(f"{_wrap(v, _vendor_color(v))} {n}" for v, n in top[:8])
        if len(top) > 8:
            shown += f" · +{len(top) - 8} more"
        lines.append(_row("edges", shown))
    if unknown:
        names = ", ".join(unknown[:3])
        if len(unknown) > 3:
            names += f", +{len(unknown) - 3}"
        lines.append(_row("unknown", f"{len(unknown)}  ({names})"))
    flag_bits = []
    if mtls:
        flag_bits.append(_wrap(f"mTLS {mtls}", _CRIT))
    if blocks:
        flag_bits.append(_wrap(f"BLOCK {blocks}", _CRIT))
    if errors:
        flag_bits.append(_wrap(f"errors {errors}", _CRIT))
    if flag_bits:
        lines.append(_row("flags", " · ".join(flag_bits)))
    if weak:
        lines.append(_row("weak", _wrap(
            f"{weak} verdict{'s' if weak > 1 else ''} "
            f"{'rest' if weak > 1 else 'rests'} on headers only (spoofable) "
            f"— confirm with --verify", _YELLOW)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown sweep (--md) — for docs, keeps markdown on purpose.
# ---------------------------------------------------------------------------


def _fmt_md_block(r: dict) -> str:
    lines = [f"### {r['hostport']}"]
    if r.get("error"):
        lines.append(f"- **ERROR**: {r['error']}")
        return "\n".join(lines)
    res = r.get("resolved") or {}
    tls = r.get("tls") or {}
    cert = tls.get("cert") or {}
    ver = r.get("verdict") or []

    lines.append(f"- **IPs**: {', '.join(res.get('ips', ['-']))}")
    if res.get("ptr"):
        lines.append(f"- **PTR**: {', '.join(res['ptr'][:3])}")
    if res.get("cname"):
        lines.append(f"- **CNAME**: {', '.join(res['cname'][:5])}")
    lines.append(f"- **TLS**: {tls.get('tls_version') or '-'}  ·  {tls.get('cipher') or '-'}"
                 f"  ·  ALPN {tls.get('alpn') or '-'}")
    if tls.get("mtls"):
        lines.append("- **MTLS**: server wants a **CLIENT certificate**")
    if cert.get("subject"):
        lines.append(f"- **Cert subject**: {cert.get('subject')}")
    if cert.get("issuer"):
        lines.append(f"- **Cert issuer**: {cert.get('issuer')}")
    if cert.get("san"):
        lines.append(f"- **SAN**: {cert.get('san')}")
    if cert.get("days_remaining") is not None:
        lines.append(f"- **Valid**: {cert.get('not_before','')[:10]} → {cert.get('not_after','')[:10]} "
                     f"({cert.get('days_remaining')}d left)")
    if cert.get("spki_sha256"):
        lines.append(f"- **SPKI SHA-256** (pin value): {cert.get('spki_sha256')}")
    if cert.get("signature"):
        lines.append(f"- **Key/sig**: {cert.get('key_type')} {cert.get('key_size','')} · {cert.get('signature')}")
    http = tls.get("http")
    if http:
        lines.append(f"- **HTTP**: {http.get('status','-')}")
        interesting = []
        for h, v in (http.get("headers") or {}).items():
            if any(re.match(hp, h) for hp in INTERESTING_HEADERS):
                interesting.append(f"{h}: {v[:80]}")
        if interesting:
            lines.append(f"- **Headers**: {', '.join(interesting)}")
    if ver:
        lines.append("- **Verdict**:")
        for m in ver:
            lines.append(f"  - {m['vendor']} — " + "; ".join(m["evidence"]))
    else:
        lines.append("- **Verdict**: no CDN/WAF signature matched (unknown edge)")
    blk = r.get("block")
    if blk:
        lines.append(f"- **Block probe** (--verify): **{blk['vendor']}** — "
                     f"{blk['title']} ({blk.get('status','')}) "
                     f"[{blk.get('confidence', 95)}% conf]")
    return "\n".join(lines)


def md_doc(results: list[dict]) -> str:
    rows = []
    for r in results:
        host = r["hostport"]
        ip = ", ".join((r.get("resolved") or {}).get("ips", ["-"])[:2])
        ver = r.get("verdict") or []
        verdict = fmt_verdict(ver)
        issuer = (r.get("tls") or {}).get("cert") and (r["tls"]["cert"].get("issuer_org") or "-") or "-"
        mtls = "**mTLS!**" if r.get("mtls") else ""
        err = r.get("error") or ""
        rows.append(f"| `{host}` | `{ip}` | {issuer} | {verdict} {mtls} | {err} |")
    return (
        "# Endpoint fingerprint sweep\n\n"
        "| Endpoint | Resolved IP | Cert issuer | CDN/WAF verdict | Notes |\n"
        "|---|---|---|---|---|\n" + "\n".join(rows) + "\n\n"
        "## Per-host detail\n\n" +
        "\n\n".join(_fmt_md_block(r) for r in results) + "\n"
    )


# Stable CSV header — one row per host, primary (top) verdict.
CSV_HEADER = [
    "host", "port", "ips", "cname", "verdict", "confidence", "signals",
    "mtls", "tls_version", "alpn", "spki", "http_status", "block", "error",
    # appended (0.1.32) — new columns go on the END so existing column
    # indexes stay valid for anything already parsing this file
    "basis", "final_host",
    # appended (0.1.35) — the attribution state, so a consumer can tell an
    # ATTRIBUTED row from an AMBIGUOUS or INTERCEPTED one without re-deriving
    "state",
]


def csv_doc(results: list[dict]) -> str:
    """Flat CSV, one row per scanned host (primary/top verdict).

    Uses the stdlib csv module for proper escaping; header row is stable
    (CSV_HEADER). Fields come straight off the result dict — no
    fingerprint-semantics changes, just a tabular projection of what was
    already probed.
    """
    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_HEADER)
    for r in results:
        ver = r.get("verdict") or []
        top = ver[0] if ver else {}
        tls = r.get("tls") or {}
        http = tls.get("http") or {}
        blk = r.get("block") or {}
        w.writerow([
            r.get("host") or r.get("hostport", ""),
            r.get("port", ""),
            ", ".join(r.get("ips", []) or []),
            ", ".join(r.get("cname", []) or []),
            top.get("vendor", ""),
            top.get("confidence", ""),
            top.get("signals", ""),
            r.get("mtls", ""),
            tls.get("tls_version", ""),
            tls.get("alpn", ""),
            r.get("spki_sha256", ""),
            http.get("status", ""),
            blk.get("vendor", ""),
            r.get("error", ""),
            _basis(top) if top else "",
            http.get("final_host", ""),
            _attribution(r).get("state", ""),
        ])
    return buf.getvalue()


# SARIF 2.1.0 schema (GitHub Code Scanning / security dashboards).
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"


def _sarif_level(r: dict) -> str:
    """Map a probe result to a SARIF severity level.

    error   — the host could not be probed (DNS failure, probe exception)
    warning — a WAF/CDN edge was positively identified (the finding a
              security dashboard wants surfaced) or --verify found a block
              page; also mTLS (server demands a client cert)
    note    — scan completed with no edge verdict (unknown origin)
    """
    if r.get("error"):
        return "error"
    if (r.get("block") or {}).get("vendor") or r.get("verdict") or r.get("mtls"):
        return "warning"
    return "note"


def sarif_doc(results: list[dict], tool_version: str = "") -> str:
    """SARIF 2.1.0 report: one result per scanned host.

    Rule ids are namespaced ``w4f/<vendor>`` (e.g. ``w4f/cloudflare``),
    ``w4f/block`` for a --verify block page, ``w4f/mtls`` for a server that
    demands a client certificate, and ``w4f/probe-error`` when the host
    could not be scanned. The host is the SARIF location; evidence and the
    confidence score ride along in properties. No fingerprint-semantics
    changes — this is a projection of the same result dicts as --json.
    """
    import json

    # rules referenced by any result, deduped in first-seen order
    rules: list[dict] = []
    rule_ids: dict[str, int] = {}  # ruleId -> index in rules

    def _rule(rule_id: str, name: str, desc: str, level: str) -> dict:
        if rule_id in rule_ids:
            return rules[rule_ids[rule_id]]
        rule_ids[rule_id] = len(rules)
        r = {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": desc},
            "defaultConfiguration": {"level": level},
        }
        rules.append(r)
        return r

    sarif_results = []
    for r in results:
        host = r.get("host") or r.get("hostport", "")
        err = r.get("error")
        blk = r.get("block") or {}
        ver = r.get("verdict") or []
        top = ver[0] if ver else {}
        _att = _attribution(r)
        level = _sarif_level(r)
        props = {
            "hostport": r.get("hostport", host),
            "port": r.get("port", ""),
            "ips": r.get("ips", []) or [],
            "cname": r.get("cname", []) or [],
            "tls_version": (r.get("tls") or {}).get("tls_version", ""),
            "alpn": (r.get("tls") or {}).get("alpn", ""),
            "mtls": bool(r.get("mtls")),
            "spki_sha256": r.get("spki_sha256", ""),
            "http_status": ((r.get("tls") or {}).get("http") or {}).get("status", ""),
            "error": err or "",
            "confidence": top.get("confidence", ""),
            "signals": top.get("signals", ""),
            "categories": top.get("categories", []) or [],
            "basis": _basis(top) if top else "",
            "state": _att.get("state", ""),
            "confidence_band": _att.get("confidence") or "",
            "evidence": top.get("evidence", []) or [],
        }

        if _att.get("state") == ATT.STATE_INTERCEPTED:
            # the identity on the wire may be the middlebox's, so this must
            # never be filed under the vendor rule for the host
            _rule("w4f/interception", "tls-interception",
                  "connection re-signed by a TLS-inspection middlebox on the "
                  "scanner's path", "warning")
            rule_id = "w4f/interception"
            by = (r.get("interception") or {}).get("by", "?")
            message = (f"{host}: TLS intercepted by {by} between the scanner and "
                       f"the target — certificate and SPKI pin describe that "
                       f"device, not this host")
        elif err:
            _rule("w4f/probe-error", "probe-error", "host could not be scanned", "error")
            rule_id = "w4f/probe-error"
            message = f"{host}: {err}"
        elif blk.get("vendor"):
            _rule("w4f/block", "block-page", "WAF block page from --verify", "warning")
            rule_id = "w4f/block"
            message = (f"{host}: WAF block page ({blk['vendor']}) — "
                       f"{blk.get('title', '')} ({blk.get('status', '')})")
        elif r.get("mtls"):
            _rule("w4f/mtls", "mutual-tls", "server demands a client certificate", "warning")
            rule_id = "w4f/mtls"
            message = f"{host}: server demands a client certificate (mTLS)"
        elif ver:
            names = ", ".join(m["vendor"] for m in ver)
            rule_id = f"w4f/{top['vendor']}"
            _rule(rule_id, top["vendor"], f"edge identified as {top['vendor']}", "warning")
            message = (f"{host}: edge {names} — top {top['vendor']} "
                       f"(confidence {top.get('confidence', 0)}%, "
                       f"{top.get('signals', 0)} signals)")
        else:
            _rule("w4f/unknown-edge", "unknown-edge",
                  "no CDN/WAF signature matched (unknown origin)", "note")
            rule_id = "w4f/unknown-edge"
            message = f"{host}: no CDN/WAF signature matched (unknown edge)"

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": host},
                    "region": {"startLine": 1},
                }
            }],
            "properties": props,
        })

    run = {
        "tool": {
            "driver": {
                "name": "w4f",
                "informationUri": "https://github.com/hdyrawan/w4f",
                "version": tool_version or "0",
                "rules": rules,
            }
        },
        "results": sarif_results,
    }
    return json.dumps({
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [run],
    }, indent=2)
