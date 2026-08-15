"""Output formatting: per-host console blocks and a doc-ready markdown sweep.

Console output is deliberately plain: aligned `label   value` lines, no
markdown bold/bullets, color only for the verdict. The markdown sweep
(--md) is separate and keeps full markdown for embedding in docs.
"""

from __future__ import annotations

import re

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


def fmt_verdict(verdict: list[dict]) -> str:
    if not verdict:
        return "unknown-edge (no signature matched)"
    return ", ".join(
        f"{m['vendor']}({m['signals']}, {m.get('confidence', 0)}%)" for m in verdict
    )


def _verdict_line(ver: list[dict]) -> str:
    """Smarter verdict formatting: the primary vendor on its own highlighted
    line; secondary vendors (origin layers) dimmed underneath."""
    if not ver:
        return _row("verdict", _wrap("no signature matched (unknown edge)", _DIM))
    lines = []
    for i, m in enumerate(ver):
        ev = "; ".join(m["evidence"])
        color = _vendor_color(m["vendor"])
        counts = _wrap(f"({m['signals']}, {m.get('confidence', 0)}%)", _DIM)
        if i == 0:
            name = _wrap(m["vendor"], _BOLD + color) if color else _wrap(m["vendor"], _BOLD)
            lines.append(_row("verdict", f"{name} {counts}: {ev}"))
        else:
            name = _wrap(m["vendor"], _DIM)
            lines.append(_row("       ", f"{name} {counts}: {ev}"))
    return "\n".join(lines)


def fmt_block(r: dict) -> str:
    if r.get("error"):
        return f"{r['hostport']}\n{_row('error', _wrap(r['error'], _RED))}"

    res = r.get("resolved") or {}
    tls = r.get("tls") or {}
    cert = tls.get("cert") or {}
    ver = r.get("verdict") or []

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
        subj = cert.get("subject") or ""
        lines.append(_row("cert", f"{cert.get('issuer_org') or cert.get('issuer')}"))
        lines.append(_row("  san", cert.get("san") or "-"))
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
        interesting = []
        for h, v in (http.get("headers") or {}).items():
            if any(re.match(hp, h) for hp in INTERESTING_HEADERS):
                interesting.append(f"{h}={v[:70]}")
        if interesting:
            # one header per line so long cookies/server strings don't wrap ugly
            for hdr in interesting[:8]:
                lines.append(_row("  hdr", hdr))

    lines.append(_verdict_line(ver))

    blk = r.get("block")
    if blk:
        lines.append(
            _row("block", _wrap(
                f"{blk['vendor']} — {blk['title']} ({blk.get('status','')})"
                f" [{blk.get('confidence', 95)}% conf]",
                _YELLOW))
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Triage view (default): summary table + compact per-host blocks.
# ---------------------------------------------------------------------------


def _flags(r: dict) -> list[str]:
    """Critical flags: mTLS / BLOCK / ERR, styled aggressively."""
    flags = []
    tls = r.get("tls") or {}
    if tls.get("mtls"):
        flags.append(_wrap("mTLS", _CRIT))
    if r.get("block"):
        blk = r["block"]
        flags.append(_wrap(f"BLOCK {blk.get('vendor', '')}".rstrip(), _CRIT))
    if r.get("error"):
        flags.append(_wrap("ERR", _CRIT))
    return flags


def fmt_summary_table(results: list[dict]) -> str:
    """Compact all-hosts table: Host | Edge | Conf | mTLS | Block | Err.

    Plain aligned text (no markdown); the edge is colored per-vendor and
    critical flags are bold red so a 20-50 host run scans in one glance.
    """
    if not results:
        return ""
    plain = []  # (host, edge, conf, mtls, block, err) — plain for width math
    for r in results:
        ver = r.get("verdict") or []
        if ver:
            edge = ver[0]["vendor"]
            conf = f"{ver[0].get('confidence', 0)}%"
        else:
            edge = "unknown"
            conf = "-"
        tls = r.get("tls") or {}
        err = r.get("error") or "-"
        if len(err) > 36:
            err = err[:33] + "..."
        plain.append((r["hostport"], edge, conf,
                      "YES" if tls.get("mtls") else "-",
                      "BLOCK" if r.get("block") else "-",
                      err))
    hw = max(len(p[0]) for p in plain)
    ew = max(len(p[1]) for p in plain)
    header = (f"{'HOST':<{hw}}  {'EDGE':<{ew}}  {'CONF':>5}  "
              f"mTLS  BLOCK  ERR")
    rows = [header]
    for r, (host, edge, conf, mtls, blk, err) in zip(results, plain):
        ver = r.get("verdict") or []
        edge_color = _vendor_color(ver[0]["vendor"]) if ver else _DIM
        host_cell = _wrap(host.ljust(hw), _CYAN)
        edge_cell = _wrap(edge.ljust(ew), edge_color) if edge_color else edge.ljust(ew)
        mtls_cell = _wrap(mtls.ljust(4), _CRIT) if mtls != "-" else mtls.ljust(4)
        blk_cell = _wrap(blk.ljust(5), _CRIT) if blk != "-" else blk.ljust(5)
        err_cell = _wrap(err, _CRIT) if err != "-" else err
        rows.append(f"{host_cell}  {edge_cell}  {conf:>5}  "
                    f"{mtls_cell}  {blk_cell}  {err_cell}")
    return "\n".join(rows)


def fmt_compact_block(r: dict) -> str:
    """Triage view per host: host + critical flags + verdict (primary
    highlighted, secondary/origin vendors dimmed). No cert/headers detail —
    that lives behind --verbose (fmt_block)."""
    head = _wrap(r["hostport"], _CYAN)
    flags = _flags(r)
    if flags:
        head += "  " + "  ".join(flags)
    lines = [head]
    ver = r.get("verdict") or []
    if ver:
        for i, m in enumerate(ver):
            counts = _wrap(f"({m['signals']}, {m.get('confidence', 0)}%)", _DIM)
            color = _vendor_color(m["vendor"])
            if i == 0:
                name = _wrap(m["vendor"], _BOLD + color) if color else _wrap(m["vendor"], _BOLD)
            else:
                name = _wrap(m["vendor"], _DIM)
            lines.append(f"    {name} {counts}")
    else:
        lines.append(_row("    ", _wrap("no signature matched (unknown edge)", _DIM)))
    if r.get("error"):
        lines.append(_row("    ", _wrap(r["error"][:100], _CRIT)))
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
            "evidence": top.get("evidence", []) or [],
        }

        if err:
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
